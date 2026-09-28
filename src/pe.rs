//! PE/COFF parser.
//!
//! Every decoded field carries the byte span it came from (file offset +
//! length, unit: byte, coordinate basis: file offset). Nothing here mutates or
//! "cleans" the input: unparseable ranges produce diagnostics instead of
//! dropping the object.

use serde::{Deserialize, Serialize};

/// Byte provenance: where in a material a value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    pub off: u32,
    pub len: u32,
}

impl Span {
    pub fn new(off: u32, len: u32) -> Self {
        Span { off, len }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeClass {
    Pe32,
    Pe32Plus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DosHeader {
    pub e_magic: String,
    pub e_lfanew: u32,
    pub magic_span: Span,
    pub lfanew_span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataDir {
    pub index: u32,
    pub name: String,
    pub rva: u32,
    pub size: u32,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionHeader {
    pub name: String,
    pub vsize: u32,
    pub vaddr: u32,
    pub raw_size: u32,
    pub raw_ptr: u32,
    pub characteristics: u32,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NtHeaders {
    pub class: PeClass,
    pub signature: String,
    pub machine: u16,
    pub num_sections: u16,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub image_base_raw: String,
    pub image_base_span: Span,
    pub data_dirs: Vec<DataDir>,
    pub sections: Vec<SectionHeader>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelocKind {
    Absolute,
    High,
    Low,
    HighLow,
    HighAdj,
    Dir64,
    Unknown(u8),
}

impl RelocKind {
    pub fn width_bits(self) -> Option<u32> {
        match self {
            RelocKind::Absolute => Some(0),
            RelocKind::High => Some(16),
            RelocKind::Low => Some(16),
            RelocKind::HighLow => Some(32),
            RelocKind::Dir64 => Some(64),
            RelocKind::HighAdj => None,
            RelocKind::Unknown(_) => None,
        }
    }
    pub fn name(self) -> String {
        match self {
            RelocKind::Absolute => "ABSOLUTE".into(),
            RelocKind::High => "HIGH".into(),
            RelocKind::Low => "LOW".into(),
            RelocKind::HighLow => "HIGHLOW".into(),
            RelocKind::HighAdj => "HIGHADJ".into(),
            RelocKind::Dir64 => "DIR64".into(),
            RelocKind::Unknown(t) => format!("UNKNOWN({})", t),
        }
    }
    fn from_type(t: u8) -> Self {
        match t {
            0 => RelocKind::Absolute,
            1 => RelocKind::High,
            2 => RelocKind::Low,
            3 => RelocKind::HighLow,
            4 => RelocKind::HighAdj,
            10 => RelocKind::Dir64,
            other => RelocKind::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelocEntry {
    pub block_page_rva: u32,
    pub rva: u32,
    pub kind: RelocKind,
    pub raw_type: u8,
    pub span: Span,
    pub block_span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImportLookup {
    Name { hint: u16, name: String, name_span: Span, hint_span: Span },
    Ordinal(u16),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportThunk {
    pub dll: String,
    pub dll_name_span: Span,
    pub lookup: ImportLookup,
    /// RVA of the slot in the IAT (FirstThunk chain).
    pub iat_rva: u32,
    pub iat_span: Span,
    pub lookup_span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub code: String,
    pub message: String,
    pub span: Option<Span>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ParsedPe {
    pub dos: Option<DosHeader>,
    pub nt: Option<NtHeaders>,
    pub relocs: Vec<RelocEntry>,
    pub imports: Vec<ImportThunk>,
    pub diagnostics: Vec<Diagnostic>,
}

pub const DIR_EXPORT: u32 = 0;
pub const DIR_IMPORT: u32 = 1;
pub const DIR_BASERELOC: u32 = 5;
pub const DIR_DEBUG: u32 = 6;

pub fn dir_name(i: u32) -> &'static str {
    match i {
        0 => "EXPORT",
        1 => "IMPORT",
        2 => "RESOURCE",
        3 => "EXCEPTION",
        4 => "CERTIFICATE",
        5 => "BASERELOC",
        6 => "DEBUG",
        7 => "ARCHITECTURE",
        8 => "GLOBAL_PTR",
        9 => "TLS",
        10 => "LOAD_CONFIG",
        11 => "BOUND_IMPORT",
        12 => "IAT",
        13 => "DELAY_IMPORT",
        14 => "CLR",
        _ => "RESERVED",
    }
}

struct R<'a> {
    b: &'a [u8],
}

impl<'a> R<'a> {
    fn u16(&self, o: u32) -> Option<u16> {
        self.b.get(o as usize..o as usize + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
    }
    fn u32(&self, o: u32) -> Option<u32> {
        self.b.get(o as usize..o as usize + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&self, o: u32) -> Option<u64> {
        self.b.get(o as usize..o as usize + 8).map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
    }
    fn cstr(&self, o: u32, max: usize) -> Option<String> {
        let start = o as usize;
        let mut end = start;
        while end < self.b.len() && end - start < max && self.b[end] != 0 {
            end += 1;
        }
        if end >= self.b.len() {
            return None;
        }
        Some(String::from_utf8_lossy(&self.b[start..end]).into_owned())
    }
}

/// Parse a PE image. `diag_span_filter` not needed: diagnostics are never fatal.
pub fn parse(bytes: &[u8]) -> ParsedPe {
    let mut out = ParsedPe::default();
    let r = R { b: bytes };
    if bytes.len() < 64 || &bytes[0..2] != b"MZ" {
        out.diagnostics.push(Diagnostic {
            code: "DOS_SIGNATURE".into(),
            message: "missing MZ signature".into(),
            span: Some(Span::new(0, 2)),
        });
        return out;
    }
    let lfanew = match r.u32(0x3c) {
        Some(v) => v,
        None => {
            out.diagnostics.push(Diagnostic {
                code: "DOS_LFANEW".into(),
                message: "e_lfanew unreadable".into(),
                span: Some(Span::new(0x3c, 4)),
            });
            return out;
        }
    };
    out.dos = Some(DosHeader {
        e_magic: "MZ".into(),
        e_lfanew: lfanew,
        magic_span: Span::new(0, 2),
        lfanew_span: Span::new(0x3c, 4),
    });
    let nt = lfanew;
    if r.u32(nt) != Some(0x0000_4550) {
        out.diagnostics.push(Diagnostic {
            code: "NT_SIGNATURE".into(),
            message: "missing PE\\0\\0 signature".into(),
            span: Some(Span::new(nt, 4)),
        });
        return out;
    }
    let coff = nt + 4;
    let machine = r.u16(coff).unwrap_or(0);
    let num_sections = r.u16(coff + 2).unwrap_or(0);
    let opt_size = r.u16(coff + 16).unwrap_or(0);
    let opt = coff + 20;
    let magic = r.u16(opt);
    let class = match magic {
        Some(0x10b) => PeClass::Pe32,
        Some(0x20b) => PeClass::Pe32Plus,
        other => {
            out.diagnostics.push(Diagnostic {
                code: "OPT_MAGIC".into(),
                message: format!("unknown optional header magic: {:?}", other),
                span: Some(Span::new(opt, 2)),
            });
            return out;
        }
    };
    let (image_base, image_base_span) = match class {
        PeClass::Pe32 => (r.u32(opt + 28).unwrap_or(0) as u64, Span::new(opt + 28, 4)),
        PeClass::Pe32Plus => (r.u64(opt + 24).unwrap_or(0), Span::new(opt + 24, 8)),
    };
    let section_alignment = r.u32(opt + 32).unwrap_or(0x1000);
    let file_alignment = r.u32(opt + 36).unwrap_or(0x200);
    let size_of_image = r.u32(opt + 56).unwrap_or(0);
    let size_of_headers = r.u32(opt + 60).unwrap_or(0);
    let num_dirs = r.u32(opt + if class == PeClass::Pe32 { 92 } else { 108 }).unwrap_or(0);
    let dirs_off = opt + if class == PeClass::Pe32 { 96 } else { 112 };
    let mut data_dirs = Vec::new();
    for i in 0..num_dirs.min(16) {
        let d = dirs_off + i * 8;
        let rva = r.u32(d).unwrap_or(0);
        let size = r.u32(d + 4).unwrap_or(0);
        data_dirs.push(DataDir {
            index: i,
            name: dir_name(i).into(),
            rva,
            size,
            span: Span::new(d, 8),
        });
    }
    let sec_tab = opt + opt_size as u32;
    let mut sections = Vec::new();
    for i in 0..num_sections {
        let s = sec_tab + i as u32 * 40;
        if (s as usize) + 40 > bytes.len() {
            out.diagnostics.push(Diagnostic {
                code: "SECTION_TABLE_RANGE".into(),
                message: format!("section header {} beyond EOF", i),
                span: Some(Span::new(s, 40)),
            });
            break;
        }
        let name = r.cstr(s, 8).unwrap_or_default();
        sections.push(SectionHeader {
            name,
            vsize: r.u32(s + 8).unwrap_or(0),
            vaddr: r.u32(s + 12).unwrap_or(0),
            raw_size: r.u32(s + 16).unwrap_or(0),
            raw_ptr: r.u32(s + 20).unwrap_or(0),
            characteristics: r.u32(s + 36).unwrap_or(0),
            span: Span::new(s, 40),
        });
    }
    out.nt = Some(NtHeaders {
        class,
        signature: "PE\\0\\0".into(),
        machine,
        num_sections,
        image_base,
        section_alignment,
        file_alignment,
        size_of_image,
        size_of_headers,
        image_base_raw: format!("0x{:x}", image_base),
        image_base_span,
        data_dirs,
        sections,
    });

    // Data directory range validation first; corrupt ranges stay diagnosed and
    // are skipped rather than causing partial table corruption.
    let valid_dirs: Vec<DataDir> = out.nt.as_ref().unwrap().data_dirs.clone();
    for d in &valid_dirs {
        if d.rva == 0 && d.size == 0 {
            continue;
        }
        if !directory_range_mappable(d, &sections, bytes.len() as u32) {
            out.diagnostics.push(Diagnostic {
                code: "CORRUPT_DIRECTORY_RANGE".into(),
                message: format!(
                    "{} directory [rva=0x{:x}, size=0x{:x}] is not fully mapped to file bytes",
                    d.name, d.rva, d.size
                ),
                span: Some(d.span),
            });
        }
    }
    if let Some(rel) = valid_dirs.iter().find(|d| d.index == DIR_BASERELOC) {
        if directory_range_mappable(rel, &sections, bytes.len() as u32) {
            parse_relocs(&r, rel, &sections, bytes.len() as u32, &mut out);
        }
    }
    if let Some(imp) = valid_dirs.iter().find(|d| d.index == DIR_IMPORT) {
        if directory_range_mappable(imp, &sections, bytes.len() as u32) {
            parse_imports(&r, imp, &sections, class, bytes.len() as u32, &mut out);
        }
    }
    out
}

/// A directory range is "mappable" iff every RVA byte resolves to a unique
/// file offset inside the file (overlap ambiguity or zero-fill does not count:
/// directory headers must be backed by raw bytes).
pub fn directory_range_mappable(d: &DataDir, sections: &[SectionHeader], file_len: u32) -> bool {
    if d.size == 0 {
        return true;
    }
    let end = match d.rva.checked_add(d.size) {
        Some(e) => e,
        None => return false,
    };
    let mut cur = d.rva;
    while cur < end {
        let mut hits: Vec<u32> = Vec::new();
        for s in sections {
            if cur >= s.vaddr && cur < s.vaddr.saturating_add(s.vsize) {
                if let Some(off) = s.file_offset_for(cur) {
                    if (off as usize) < file_len as usize {
                        hits.push(off);
                    }
                }
            }
        }
        if hits.len() != 1 {
            return false;
        }
        cur += 1;
    }
    true
}

impl SectionHeader {
    pub fn file_offset_for(&self, rva: u32) -> Option<u32> {
        if rva < self.vaddr {
            return None;
        }
        let delta = rva - self.vaddr;
        if delta >= self.vsize.min(self.raw_size) || delta >= self.raw_size {
            return None;
        }
        Some(self.raw_ptr + delta)
    }
}

fn parse_relocs(
    r: &R,
    dir: &DataDir,
    sections: &[SectionHeader],
    file_len: u32,
    out: &mut ParsedPe,
) {
    let mut off = dir.rva;
    let dir_end = dir.rva + dir.size;
    while off + 8 <= dir_end {
        let page = match rva_to_file(off, sections, file_len) {
            Some(fo) => match r.u32(fo) {
                Some(v) => v,
                None => break,
            },
            None => break,
        };
        let block_size = match rva_to_file(off + 4, sections, file_len) {
            Some(fo) => match r.u32(fo) {
                Some(v) => v,
                None => break,
            },
            None => break,
        };
        if block_size < 8 {
            out.diagnostics.push(Diagnostic {
                code: "RELOC_BLOCK_SIZE".into(),
                message: format!("reloc block at rva 0x{:x} smaller than header", off),
                span: Some(Span::new(off + 4, 4)),
            });
            break;
        }
        let count = (block_size / 2 - 4) as usize;
        for i in 0..count {
            let ent_rva = off + 8 + i as u32 * 2;
            let fo = match rva_to_file(ent_rva, sections, file_len) {
                Some(fo) => fo,
                None => {
                    out.diagnostics.push(Diagnostic {
                        code: "RELOC_ENTRY_RANGE".into(),
                        message: format!("reloc entry {} not file-backed", i),
                        span: Some(Span::new(ent_rva, 2)),
                    });
                    continue;
                }
            };
            let word = match r.u16(fo) {
                Some(v) => v,
                None => continue,
            };
            let typ = (word >> 12) as u8;
            let delta = (word & 0x0fff) as u32;
            let kind = RelocKind::from_type(typ);
            if matches!(kind, RelocKind::Absolute) {
                continue;
            }
            out.relocs.push(RelocEntry {
                block_page_rva: page,
                rva: page + delta,
                kind,
                raw_type: typ,
                span: Span::new(ent_rva, 2),
                block_span: Span::new(off, block_size),
            });
        }
        off += block_size;
    }
}

#[allow(clippy::too_many_arguments)]
fn parse_imports(
    r: &R,
    dir: &DataDir,
    sections: &[SectionHeader],
    class: PeClass,
    file_len: u32,
    out: &mut ParsedPe,
) {
    let ptr_size: u32 = match class {
        PeClass::Pe32 => 4,
        PeClass::Pe32Plus => 8,
    };
    let ord_flag: u64 = match class {
        PeClass::Pe32 => 0x8000_0000,
        PeClass::Pe32Plus => 1 << 63,
    };
    let mut desc = dir.rva;
    loop {
        let desc_fo = match rva_to_file(desc, sections, file_len) {
            Some(fo) => fo,
            None => {
                out.diagnostics.push(Diagnostic {
                    code: "IMPORT_DESC_RANGE".into(),
                    message: format!("import descriptor at rva 0x{:x} not file-backed", desc),
                    span: Some(Span::new(desc, 20)),
                });
                return;
            }
        };
        let oft = r.u32(desc_fo).unwrap_or(0);
        let name_rva = r.u32(desc_fo + 12).unwrap_or(0);
        let ft = r.u32(desc_fo + 16).unwrap_or(0);
        if oft == 0 && name_rva == 0 && ft == 0 {
            break;
        }
        if name_rva == 0 {
            out.diagnostics.push(Diagnostic {
                code: "IMPORT_NAME_RANGE".into(),
                message: format!("import descriptor at rva 0x{:x} has no name", desc),
                span: Some(Span::new(desc + 12, 4)),
            });
            desc += 20;
            continue;
        }
        let name_fo = match rva_to_file(name_rva, sections, file_len) {
            Some(fo) => fo,
            None => {
                out.diagnostics.push(Diagnostic {
                    code: "IMPORT_NAME_RANGE".into(),
                    message: format!("DLL name rva 0x{:x} not file-backed", name_rva),
                    span: Some(Span::new(desc + 12, 4)),
                });
                desc += 20;
                continue;
            }
        };
        let dll = r.cstr(name_fo, 256).unwrap_or_else(|| "?".into());
        let chain = if oft != 0 { oft } else { ft };
        let mut slot = 0u32;
        loop {
            let ent_rva = chain + slot * ptr_size;
            let iat_rva = ft + slot * ptr_size;
            let ent_fo = match rva_to_file(ent_rva, sections, file_len) {
                Some(fo) => fo,
                None => {
                    out.diagnostics.push(Diagnostic {
                        code: "IMPORT_THUNK_RANGE".into(),
                        message: format!("{}: thunk slot {} not file-backed", dll, slot),
                        span: Some(Span::new(ent_rva, ptr_size)),
                    });
                    return;
                }
            };
            let value = match class {
                PeClass::Pe32 => r.u32(ent_fo).unwrap_or(0) as u64,
                PeClass::Pe32Plus => r.u64(ent_fo).unwrap_or(0),
            };
            if value == 0 {
                break;
            }
            let lookup = if value & ord_flag != 0 {
                ImportLookup::Ordinal(value as u16)
            } else {
                let hn_rva = value as u32;
                match rva_to_file(hn_rva, sections, file_len) {
                    Some(hn_fo) => {
                        let hint = r.u16(hn_fo).unwrap_or(0);
                        let nm = r.cstr(hn_fo + 2, 1024).unwrap_or_else(|| "?".into());
                        ImportLookup::Name {
                            hint,
                            name: nm,
                            name_span: Span::new(hn_fo + 2, 0),
                            hint_span: Span::new(hn_fo, 2),
                        }
                    }
                    None => {
                        out.diagnostics.push(Diagnostic {
                            code: "IMPORT_HINTNAME_RANGE".into(),
                            message: format!("{}: hint/name rva 0x{:x} not file-backed", dll, hn_rva),
                            span: Some(Span::new(ent_rva, ptr_size)),
                        });
                        ImportLookup::Ordinal(value as u16)
                    }
                }
            };
            out.imports.push(ImportThunk {
                dll: dll.clone(),
                dll_name_span: Span::new(name_rva, 0),
                lookup,
                iat_rva,
                iat_span: Span::new(iat_rva, ptr_size),
                lookup_span: Span::new(ent_rva, ptr_size),
            });
            slot += 1;
        }
        desc += 20;
    }
}

/// Resolve an RVA to a file offset. Returns `None` for unmapped, zero-fill and
/// ambiguous (overlap) RVA alike; callers that need the full candidate set use
/// [`loader::rva_candidates`].
pub fn rva_to_file(rva: u32, sections: &[SectionHeader], file_len: u32) -> Option<u32> {
    let mut hit: Option<u32> = None;
    for s in sections {
        if let Some(off) = s.file_offset_for(rva) {
            if (off as usize) < file_len as usize {
                if hit.is_some() {
                    return None;
                }
                hit = Some(off);
            }
        }
    }
    hit
}
