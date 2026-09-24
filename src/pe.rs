//! PE parsing with byte-provenance spans. Raw bytes are never mutated;
//! every parsed value records the file range it was read from.

use serde::{Deserialize, Serialize};

pub const DIR_EXPORT: usize = 0;
pub const DIR_IMPORT: usize = 1;
pub const DIR_BASERELOC: usize = 5;
pub const DIR_COUNT: usize = 16;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Span {
    pub offset: u32,
    pub len: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataDir {
    pub index: usize,
    pub name: &'static str,
    pub rva: u32,
    pub size: u32,
    pub span: Span,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Section {
    pub ordinal: usize,
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_ptr: u32,
    pub characteristics: u32,
    pub span: Span,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelocEntry {
    pub raw_type: u8,
    pub type_name: String,
    pub offset_in_page: u16,
    pub page_rva: u32,
    pub span: Span,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelocBlock {
    pub page_rva: u32,
    pub block_size: u32,
    pub entries: Vec<RelocEntry>,
    pub span: Span,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ThunkKind {
    Ordinal { ordinal: u16 },
    Name { hint: u16, name: String, name_span: Span },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Thunk {
    pub raw_value: u64,
    pub kind: ThunkKind,
    pub ilt_span: Span,
    pub iat_rva: u32,
    pub iat_span: Span,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImportDescriptor {
    pub dll_name: String,
    pub dll_name_span: Span,
    pub ilt_rva: u32,
    pub iat_rva: u32,
    pub thunks: Vec<Thunk>,
    pub span: Span,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Diagnostic {
    pub code: String,
    pub message: String,
    pub span: Option<Span>,
    pub rva: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeImage {
    pub e_lfanew: u32,
    pub e_lfanew_span: Span,
    pub machine: u16,
    pub num_sections: u16,
    pub characteristics: u16,
    pub pe_magic: u16,
    pub is_pe32_plus: bool,
    pub image_base: u64,
    pub image_base_span: Span,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub nt_headers_span: Span,
    pub data_dirs: Vec<DataDir>,
    pub sections: Vec<Section>,
    pub reloc_blocks: Vec<RelocBlock>,
    pub imports: Vec<ImportDescriptor>,
    pub diagnostics: Vec<Diagnostic>,
}

pub const DIR_NAMES: [&str; DIR_COUNT] = [
    "export", "import", "resource", "exception", "certificate", "basereloc",
    "debug", "architecture", "globalptr", "tls", "loadconfig", "boundimport",
    "iat", "delayimport", "clr", "reserved",
];

fn r16(b: &[u8], o: usize) -> u16 { u16::from_le_bytes([b[o], b[o + 1]]) }
fn r32(b: &[u8], o: usize) -> u32 { u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) }
fn r64(b: &[u8], o: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(v)
}

/// Map an RVA to a file offset using the *first* matching section with raw
/// backing. Returns None when unmapped or zero-fill-only. Full multi-candidate
/// semantics live in `load::map_rva`; this helper is only for the parser's own
/// directory walking and records a diagnostic when the directory is corrupt.
fn rva_to_off_first(img_sections: &[Section], rva: u32) -> Option<u32> {
    for s in img_sections {
        let span = s.virtual_size.max(s.raw_size);
        if rva >= s.virtual_address && rva < s.virtual_address + span {
            let delta = rva - s.virtual_address;
            if delta < s.raw_size {
                return Some(s.raw_ptr + delta);
            }
            return None;
        }
    }
    None
}

fn read_cstr(b: &[u8], off: usize) -> (String, usize) {
    let mut end = off;
    while end < b.len() && b[end] != 0 {
        end += 1;
    }
    (String::from_utf8_lossy(&b[off..end]).into_owned(), end - off + 1)
}

pub fn parse_pe(bytes: &[u8]) -> Result<PeImage, String> {
    if bytes.len() < 0x40 || &bytes[0..2] != b"MZ" {
        return Err("missing DOS MZ magic".into());
    }
    let e_lfanew = r32(bytes, 0x3C);
    let pe_off = e_lfanew as usize;
    if pe_off + 24 > bytes.len() || &bytes[pe_off..pe_off + 4] != b"PE\0\0" {
        return Err("missing NT PE signature at e_lfanew".into());
    }
    let coff = pe_off + 4;
    let machine = r16(bytes, coff);
    let num_sections = r16(bytes, coff + 2);
    let characteristics = r16(bytes, coff + 18);
    let opt_size = r16(bytes, coff + 16) as usize;
    let opt = coff + 20;
    if opt + opt_size > bytes.len() {
        return Err("optional header truncated".into());
    }
    let pe_magic = r16(bytes, opt);
    let is_pe32_plus = match pe_magic {
        0x20B => true,
        0x10B => false,
        m => return Err(format!("unknown optional-header magic 0x{m:04x}")),
    };
    let (image_base, image_base_span) = if is_pe32_plus {
        (r64(bytes, opt + 24), Span { offset: (opt + 24) as u32, len: 8 })
    } else {
        (r32(bytes, opt + 28) as u64, Span { offset: (opt + 28) as u32, len: 4 })
    };
    let section_alignment = r32(bytes, opt + 32);
    let file_alignment = r32(bytes, opt + 36);
    let size_of_image = r32(bytes, opt + 56);
    let size_of_headers = r32(bytes, opt + 60);
    let num_dirs = r32(bytes, opt + if is_pe32_plus { 108 } else { 92 }) as usize;
    let dirs_off = opt + if is_pe32_plus { 112 } else { 96 };

    let mut data_dirs = Vec::new();
    let mut diagnostics = Vec::new();
    for i in 0..num_dirs.min(DIR_COUNT) {
        let o = dirs_off + i * 8;
        if o + 8 > opt + opt_size || o + 8 > bytes.len() {
            break;
        }
        let rva = r32(bytes, o);
        let size = r32(bytes, o + 4);
        data_dirs.push(DataDir {
            index: i,
            name: DIR_NAMES[i],
            rva,
            size,
            span: Span { offset: o as u32, len: 8 },
        });
        if rva != 0 && (rva >= size_of_image || size > size_of_image || rva + size > size_of_image) {
            diagnostics.push(Diagnostic {
                code: "corrupt-directory-range".into(),
                message: format!(
                    "data directory {} has RVA 0x{rva:08x} size 0x{size:08x} outside image (size_of_image 0x{size_of_image:08x})",
                    DIR_NAMES[i]
                ),
                span: Some(Span { offset: o as u32, len: 8 }),
                rva: Some(rva),
            });
        }
    }

    let sec_off = opt + opt_size;
    let mut sections = Vec::new();
    for i in 0..num_sections as usize {
        let o = sec_off + i * 40;
        if o + 40 > bytes.len() {
            return Err("section table truncated".into());
        }
        let name_bytes = &bytes[o..o + 8];
        let name = String::from_utf8_lossy(
            &name_bytes[..name_bytes.iter().position(|&c| c == 0).unwrap_or(8)],
        )
        .into_owned();
        sections.push(Section {
            ordinal: i,
            name,
            virtual_size: r32(bytes, o + 8),
            virtual_address: r32(bytes, o + 12),
            raw_size: r32(bytes, o + 16),
            raw_ptr: r32(bytes, o + 20),
            characteristics: r32(bytes, o + 36),
            span: Span { offset: o as u32, len: 40 },
        });
    }

    let dir = |idx: usize| data_dirs.iter().find(|d| d.index == idx).cloned();
    let dir_ok = |d: &Option<DataDir>| -> Option<&DataDir> {
        d.as_ref().filter(|d| {
            d.rva != 0
                && d.rva < size_of_image
                && d.size <= size_of_image
                && d.rva + d.size <= size_of_image
        })
    };

    // Base relocations (skipped entirely when the directory range is corrupt).
    let mut reloc_blocks = Vec::new();
    if let Some(d) = dir_ok(&dir(DIR_BASERELOC)) {
        let mut cur = d.rva;
        let end = d.rva + d.size;
        while cur + 8 <= end {
            let Some(off) = rva_to_off_first(&sections, cur) else { break };
            let o = off as usize;
            if o + 8 > bytes.len() {
                break;
            }
            let page_rva = r32(bytes, o);
            let block_size = r32(bytes, o + 4);
            if block_size < 8 || cur + block_size > end {
                break;
            }
            let mut entries = Vec::new();
            let mut e = o + 8;
            while e + 2 <= o + block_size as usize && e + 2 <= bytes.len() {
                let raw = r16(bytes, e);
                let raw_type = (raw >> 12) as u8;
                let type_name = match raw_type {
                    0 => "ABSOLUTE",
                    3 => "HIGHLOW",
                    10 => "DIR64",
                    _ => "UNKNOWN",
                }
                .to_string();
                entries.push(RelocEntry {
                    raw_type,
                    type_name,
                    offset_in_page: raw & 0x0FFF,
                    page_rva,
                    span: Span { offset: e as u32, len: 2 },
                });
                e += 2;
            }
            reloc_blocks.push(RelocBlock {
                page_rva,
                block_size,
                entries,
                span: Span { offset: o as u32, len: block_size },
            });
            cur += block_size;
        }
    }

    // Imports.
    let mut imports = Vec::new();
    if let Some(d) = dir_ok(&dir(DIR_IMPORT)) {
        let mut cur = d.rva;
        loop {
            let Some(off) = rva_to_off_first(&sections, cur) else { break };
            let o = off as usize;
            if o + 20 > bytes.len() {
                break;
            }
            let ilt_rva = r32(bytes, o);
            let name_rva = r32(bytes, o + 12);
            let iat_rva = r32(bytes, o + 16);
            if ilt_rva == 0 && name_rva == 0 && iat_rva == 0 {
                break; // null descriptor terminator
            }
            let (dll_name, dll_len) = match rva_to_off_first(&sections, name_rva) {
                Some(no) if (no as usize) < bytes.len() => read_cstr(bytes, no as usize),
                _ => {
                    diagnostics.push(Diagnostic {
                        code: "import-name-unmapped".into(),
                        message: format!("import descriptor DLL name RVA 0x{name_rva:08x} unmapped"),
                        span: Some(Span { offset: o as u32, len: 20 }),
                        rva: Some(name_rva),
                    });
                    (String::new(), 0)
                }
            };
            let dll_name_span = Span {
                offset: rva_to_off_first(&sections, name_rva).unwrap_or(0),
                len: dll_len as u32,
            };
            let thunk_rva = if ilt_rva != 0 { ilt_rva } else { iat_rva };
            let mut thunks = Vec::new();
            let mut t = thunk_rva;
            let mut iat = iat_rva;
            loop {
                let Some(toff) = rva_to_off_first(&sections, t) else { break };
                let to = toff as usize;
                if to + 8 > bytes.len() {
                    break;
                }
                let val = r64(bytes, to);
                let iat_span = Span {
                    offset: rva_to_off_first(&sections, iat).unwrap_or(0),
                    len: 8,
                };
                if val == 0 {
                    break;
                }
                let kind = if val & 0x8000_0000_0000_0000 != 0 {
                    ThunkKind::Ordinal { ordinal: (val & 0xFFFF) as u16 }
                } else {
                    let hn_rva = val as u32;
                    match rva_to_off_first(&sections, hn_rva) {
                        Some(ho) if (ho as usize) + 2 <= bytes.len() => {
                            let hint = r16(bytes, ho as usize);
                            let (name, nlen) = read_cstr(bytes, ho as usize + 2);
                            ThunkKind::Name {
                                hint,
                                name,
                                name_span: Span { offset: ho, len: 2 + nlen as u32 },
                            }
                        }
                        _ => {
                            diagnostics.push(Diagnostic {
                                code: "hint-name-unmapped".into(),
                                message: format!("hint/name RVA 0x{hn_rva:08x} unmapped"),
                                span: None,
                                rva: Some(hn_rva),
                            });
                            ThunkKind::Name { hint: 0, name: String::new(), name_span: Span { offset: 0, len: 0 } }
                        }
                    }
                };
                thunks.push(Thunk {
                    raw_value: val,
                    kind,
                    ilt_span: Span { offset: toff, len: 8 },
                    iat_rva: iat,
                    iat_span,
                });
                t += 8;
                iat += 8;
            }
            imports.push(ImportDescriptor {
                dll_name,
                dll_name_span,
                ilt_rva,
                iat_rva,
                thunks,
                span: Span { offset: o as u32, len: 20 },
            });
            cur += 20;
        }
    }

    Ok(PeImage {
        e_lfanew,
        e_lfanew_span: Span { offset: 0x3C, len: 4 },
        machine,
        num_sections,
        characteristics,
        pe_magic,
        is_pe32_plus,
        image_base,
        image_base_span,
        size_of_image,
        size_of_headers,
        section_alignment,
        file_alignment,
        nt_headers_span: Span { offset: pe_off as u32, len: (4 + 20 + opt_size) as u32 },
        data_dirs,
        sections,
        reloc_blocks,
        imports,
        diagnostics,
    })
}

