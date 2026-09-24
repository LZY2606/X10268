//! PE byte parsing. Everything here is a *source* layer reading: raw byte
//! ranges are recorded so provenance back to the original bytes is kept.

use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct Diagnostic {
    pub kind: String,
    pub message: String,
    pub rva: Option<u64>,
    pub file_offset: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DataDirectory {
    pub index: usize,
    pub name: String,
    pub rva: u32,
    pub size: u32,
    pub file_offset: u64,
    pub corrupt: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Section {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub header_offset: u64,
}

impl Section {
    /// Bytes the section occupies in the virtual image.
    pub fn mapped_size(&self) -> u64 {
        self.virtual_size.max(self.raw_size) as u64
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RelocEntry {
    /// Full RVA of the relocation target (page_rva + entry offset).
    pub rva: u32,
    pub type_: u8,
    /// File offset of this 2-byte entry record itself.
    pub file_offset: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct RelocBlock {
    pub page_rva: u32,
    pub file_offset: u64,
    pub entries: Vec<RelocEntry>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ImportThunk {
    pub thunk_rva: u32,
    pub file_offset: u64,
    pub ordinal: Option<u16>,
    pub name: Option<String>,
    pub hint: Option<u16>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ImportDescriptor {
    pub dll: String,
    pub ilt_rva: u32,
    pub iat_rva: u32,
    pub desc_rva: u32,
    pub file_offset: u64,
    pub thunks: Vec<ImportThunk>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PeImage {
    pub e_magic: String,
    pub e_lfanew: u32,
    pub machine: u16,
    pub number_of_sections: u16,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub number_of_rva_and_sizes: u32,
    pub optional_header_offset: u64,
    pub directories: Vec<DataDirectory>,
    pub sections: Vec<Section>,
    pub reloc_blocks: Vec<RelocBlock>,
    pub imports: Vec<ImportDescriptor>,
    pub diagnostics: Vec<Diagnostic>,
}

pub const DIRECTORY_NAMES: [&str; 16] = [
    "export", "import", "resource", "exception", "security", "basereloc", "debug",
    "architecture", "globalptr", "tls", "load_config", "bound_import", "iat",
    "delay_import", "clr", "reserved",
];

struct R<'a> {
    b: &'a [u8],
}
impl<'a> R<'a> {
    fn u16(&self, o: usize) -> Option<u16> {
        Some(u16::from_le_bytes(self.b.get(o..o + 2)?.try_into().ok()?))
    }
    fn u32(&self, o: usize) -> Option<u32> {
        Some(u32::from_le_bytes(self.b.get(o..o + 4)?.try_into().ok()?))
    }
    fn cstr(&self, o: usize) -> Option<String> {
        if o >= self.b.len() {
            return None;
        }
        let mut e = o;
        while e < self.b.len() && self.b[e] != 0 && e - o < 256 {
            e += 1;
        }
        Some(String::from_utf8_lossy(&self.b[o..e]).into_owned())
    }
}

/// First-hit RVA -> file offset used only by the parser to walk structures.
/// The loader layer (loader::map_rva) keeps the full multi-candidate view.
pub fn rva_to_file_first(pe: &PeImage, rva: u64) -> Option<usize> {
    for s in &pe.sections {
        let va = s.virtual_address as u64;
        let end = va + s.mapped_size();
        if rva >= va && rva < end {
            let off = rva - va;
            if off < s.raw_size as u64 {
                return Some((s.raw_offset as u64 + off) as usize);
            }
            return None; // zero-fill region: no file bytes
        }
    }
    None
}

pub fn parse(bytes: &[u8]) -> PeImage {
    let r = R { b: bytes };
    let mut diags: Vec<Diagnostic> = Vec::new();

    let e_magic = r.cstr(0).map(|s| s.chars().take(2).collect()).unwrap_or_default();
    if !bytes.starts_with(b"MZ") {
        diags.push(Diagnostic {
            kind: "bad_dos_magic".into(),
            message: "DOS header does not start with MZ".into(),
            rva: None,
            file_offset: Some(0),
        });
    }
    let e_lfanew = r.u32(0x3C).unwrap_or(0);
    let nt = e_lfanew as usize;
    if bytes.get(nt..nt + 4) != Some(b"PE\0\0") {
        diags.push(Diagnostic {
            kind: "bad_nt_signature".into(),
            message: "NT signature is not PE\\0\\0".into(),
            rva: None,
            file_offset: Some(nt as u64),
        });
    }
    let machine = r.u16(nt + 4).unwrap_or(0);
    let number_of_sections = r.u16(nt + 6).unwrap_or(0);
    let size_of_optional = r.u16(nt + 20).unwrap_or(0) as usize;
    let opt = nt + 24;
    let magic = r.u16(opt).unwrap_or(0);
    if magic != 0x10B {
        diags.push(Diagnostic {
            kind: "unsupported_optional_magic".into(),
            message: format!("optional header magic 0x{magic:04X}; this workbench models PE32"),
            rva: None,
            file_offset: Some(opt as u64),
        });
    }
    let image_base = r.u32(opt + 28).unwrap_or(0) as u64;
    let section_alignment = r.u32(opt + 32).unwrap_or(0);
    let file_alignment = r.u32(opt + 36).unwrap_or(0);
    let size_of_image = r.u32(opt + 56).unwrap_or(0);
    let size_of_headers = r.u32(opt + 60).unwrap_or(0);
    let number_of_rva_and_sizes = r.u32(opt + 92).unwrap_or(0);

    // Data directories (raw entry offset kept for provenance).
    let mut directories = Vec::new();
    let dd = opt + 96;
    for i in 0..DIRECTORY_NAMES.len().min(number_of_rva_and_sizes as usize) {
        let eo = dd + i * 8;
        let rva = r.u32(eo).unwrap_or(0);
        let size = r.u32(eo + 4).unwrap_or(0);
        let corrupt = rva != 0 && (size == 0 || rva as u64 + size as u64 > size_of_image as u64);
        if corrupt {
            diags.push(Diagnostic {
                kind: "corrupt_directory".into(),
                message: format!(
                    "directory[{}] {} range 0x{rva:08X}..0x{:08X} exceeds SizeOfImage 0x{size_of_image:08X}",
                    i, DIRECTORY_NAMES[i], rva as u64 + size as u64
                ),
                rva: Some(rva as u64),
                file_offset: Some(eo as u64),
            });
        }
        directories.push(DataDirectory {
            index: i,
            name: DIRECTORY_NAMES[i].into(),
            rva,
            size,
            file_offset: eo as u64,
            corrupt,
        });
    }

    // Section headers.
    let mut sections = Vec::new();
    let sh = opt + size_of_optional;
    for i in 0..number_of_sections as usize {
        let o = sh + i * 40;
        let name = r.cstr(o).unwrap_or_default();
        let name: String = name.chars().take(8).collect();
        let virtual_size = r.u32(o + 8).unwrap_or(0);
        let virtual_address = r.u32(o + 12).unwrap_or(0);
        let raw_size = r.u32(o + 16).unwrap_or(0);
        let raw_offset = r.u32(o + 20).unwrap_or(0);
        sections.push(Section {
            name,
            virtual_address,
            virtual_size,
            raw_offset,
            raw_size,
            header_offset: o as u64,
        });
    }

    let pe = PeImage {
        e_magic,
        e_lfanew,
        machine,
        number_of_sections,
        image_base,
        section_alignment,
        file_alignment,
        size_of_image,
        size_of_headers,
        number_of_rva_and_sizes,
        optional_header_offset: opt as u64,
        directories,
        sections,
        reloc_blocks: Vec::new(),
        imports: Vec::new(),
        diagnostics: diags,
    };

    let mut pe = pe;
    parse_relocations(&r, &mut pe);
    parse_imports(&r, &mut pe);
    pe
}

fn parse_relocations(r: &R, pe: &mut PeImage) {
    let dir = match pe.directories.get(5) {
        Some(d) if d.rva != 0 && !d.corrupt => d.clone(),
        _ => return,
    };
    let mut off = match rva_to_file_first(pe, dir.rva as u64) {
        Some(o) => o,
        None => {
            pe.diagnostics.push(Diagnostic {
                kind: "unmapped_reloc_directory".into(),
                message: "base relocation directory RVA does not map to file bytes".into(),
                rva: Some(dir.rva as u64),
                file_offset: None,
            });
            return;
        }
    };
    let end = off + dir.size as usize;
    let mut guard = 0;
    while off + 8 <= end && guard < 512 {
        guard += 1;
        let block_off = off;
        let page_rva = r.u32(off).unwrap_or(0);
        let block_size = r.u32(off + 4).unwrap_or(0) as usize;
        if block_size < 8 || off + block_size > r.b.len() {
            pe.diagnostics.push(Diagnostic {
                kind: "corrupt_reloc_block".into(),
                message: format!("reloc block at file 0x{off:X} has invalid size {block_size}"),
                rva: Some(page_rva as u64),
                file_offset: Some(off as u64),
            });
            break;
        }
        let mut entries = Vec::new();
        let mut eo = off + 8;
        while eo + 2 <= off + block_size {
            let raw = r.u16(eo).unwrap_or(0);
            entries.push(RelocEntry {
                rva: page_rva.wrapping_add((raw & 0x0FFF) as u32),
                type_: (raw >> 12) as u8,
                file_offset: eo as u64,
            });
            eo += 2;
        }
        pe.reloc_blocks.push(RelocBlock {
            page_rva,
            file_offset: block_off as u64,
            entries,
        });
        off += block_size;
    }
}

fn parse_imports(r: &R, pe: &mut PeImage) {
    let dir = match pe.directories.get(1) {
        Some(d) if d.rva != 0 && !d.corrupt => d.clone(),
        _ => return,
    };
    let mut off = match rva_to_file_first(pe, dir.rva as u64) {
        Some(o) => o,
        None => {
            pe.diagnostics.push(Diagnostic {
                kind: "unmapped_import_directory".into(),
                message: "import directory RVA does not map to file bytes".into(),
                rva: Some(dir.rva as u64),
                file_offset: None,
            });
            return;
        }
    };
    let mut guard = 0;
    loop {
        guard += 1;
        if guard > 256 || off + 20 > r.b.len() {
            break;
        }
        let oft = r.u32(off).unwrap_or(0);
        let name_rva = r.u32(off + 12).unwrap_or(0);
        let ft = r.u32(off + 16).unwrap_or(0);
        if oft == 0 && name_rva == 0 && ft == 0 {
            break;
        }
        let desc_rva = dir.rva + (off as u32).wrapping_sub(
            rva_to_file_first(pe, dir.rva as u64).unwrap_or(0) as u32,
        );
        let dll = rva_to_file_first(pe, name_rva as u64)
            .and_then(|no| r.cstr(no))
            .unwrap_or_else(|| "<unreadable>".to_string());
        let ilt_rva = if oft != 0 { oft } else { ft };
        let mut thunks = Vec::new();
        if let Some(mut toff) = rva_to_file_first(pe, ilt_rva as u64) {
            let mut tguard = 0;
            loop {
                tguard += 1;
                if tguard > 1024 || toff + 4 > r.b.len() {
                    break;
                }
                let val = r.u32(toff).unwrap_or(0);
                if val == 0 {
                    break;
                }
                let thunk_rva = ilt_rva + (toff as u32).wrapping_sub(
                    rva_to_file_first(pe, ilt_rva as u64).unwrap_or(0) as u32,
                );
                if val & 0x8000_0000 != 0 {
                    thunks.push(ImportThunk {
                        thunk_rva,
                        file_offset: toff as u64,
                        ordinal: Some((val & 0xFFFF) as u16),
                        name: None,
                        hint: None,
                    });
                } else {
                    let (hint, name) = match rva_to_file_first(pe, val as u64) {
                        Some(ho) => (r.u16(ho), r.cstr(ho + 2)),
                        None => {
                            pe.diagnostics.push(Diagnostic {
                                kind: "unmapped_hint_name".into(),
                                message: format!("hint/name RVA 0x{val:08X} unmapped"),
                                rva: Some(val as u64),
                                file_offset: None,
                            });
                            (None, None)
                        }
                    };
                    thunks.push(ImportThunk {
                        thunk_rva,
                        file_offset: toff as u64,
                        ordinal: None,
                        name,
                        hint,
                    });
                }
                toff += 4;
            }
        }
        pe.imports.push(ImportDescriptor {
            dll,
            ilt_rva,
            iat_rva: ft,
            desc_rva,
            file_offset: off as u64,
            thunks,
        });
        off += 20;
    }
}
