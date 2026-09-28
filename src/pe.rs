//! Minimal, non-destructive PE32/PE32+ parser.
//!
//! The parser never "repairs" the image. Structural problems become
//! [`Diag`] entries carrying the byte range they refer to. Every derived
//! scalar keeps the byte window it was decoded from via [`ByteSpan`].

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeClass {
    Pe32,
    Pe32Plus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteSpan {
    pub off: u32,
    pub len: u32,
    pub hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scalar {
    pub value: String,
    pub raw: String,
    pub width: u8,
    pub at: ByteSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DosHeader {
    pub e_magic: Scalar,
    pub e_lfanew: Scalar,
    pub fields: Vec<(String, Scalar)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionHeader {
    pub name: String,
    pub virtual_size: Scalar,
    pub virtual_address: Scalar,
    pub raw_size: Scalar,
    pub raw_pointer: Scalar,
    pub characteristics: Scalar,
    pub header_span: ByteSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataDirectory {
    pub index: u8,
    pub name: String,
    pub rva: Scalar,
    pub size: Scalar,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocEntry {
    pub rva: u32,
    pub typ: u8,
    pub type_name: String,
    pub patch_offset: u32,
    pub field_width_bits: u8,
    pub span: ByteSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocBlock {
    pub page_rva: Scalar,
    pub block_size: Scalar,
    pub entries: Vec<RelocEntry>,
    pub span: ByteSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportThunk {
    pub is_ordinal: bool,
    pub ordinal: Option<u16>,
    pub hint_name_rva: Option<u32>,
    pub hint: Option<u16>,
    pub name: Option<String>,
    pub hint_span: Option<ByteSpan>,
    pub name_span: Option<ByteSpan>,
    pub ilt_span: ByteSpan,
    pub iat_span: ByteSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportDescriptor {
    pub dll_name: String,
    pub dll_name_span: ByteSpan,
    pub original_first_thunk: Scalar,
    pub time_date_stamp: Scalar,
    pub forwarder_chain: Scalar,
    pub name_rva: Scalar,
    pub first_thunk: Scalar,
    pub thunks: Vec<ImportThunk>,
    pub span: ByteSpan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diag {
    pub code: String,
    pub severity: Severity,
    pub message: String,
    pub at: Option<ByteSpan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeImage {
    pub pe_class: PeClass,
    pub file_size: u32,
    pub dos: DosHeader,
    pub nt_span: ByteSpan,
    pub signature_span: ByteSpan,
    pub machine: Scalar,
    pub num_sections: Scalar,
    pub time_date_stamp: Scalar,
    pub characteristics: Scalar,
    pub optional_magic: Scalar,
    pub image_base: Scalar,
    pub section_alignment: Scalar,
    pub file_alignment: Scalar,
    pub size_of_image: Scalar,
    pub size_of_headers: Scalar,
    pub sections: Vec<SectionHeader>,
    pub directories: Vec<DataDirectory>,
    pub reloc_blocks: Vec<RelocBlock>,
    pub imports: Vec<ImportDescriptor>,
    pub diags: Vec<Diag>,
}

pub const DIRECTORY_NAMES: &[&str] = &[
    "EXPORT",
    "IMPORT",
    "RESOURCE",
    "EXCEPTION",
    "SECURITY",
    "BASERELOC",
    "DEBUG",
    "ARCHITECTURE",
    "GLOBALPTR",
    "TLS",
    "LOAD_CONFIG",
    "BOUND_IMPORT",
    "IAT",
    "DELAY_IMPORT",
    "CLR",
];

fn u16le(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}
fn u32le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
fn u64le(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

fn hex_of(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn span_at(buf: &[u8], off: usize, len: usize) -> Option<ByteSpan> {
    let end = off.checked_add(len)?;
    if end > buf.len() {
        return None;
    }
    Some(ByteSpan {
        off: off as u32,
        len: len as u32,
        hex: hex_of(&buf[off..end]),
    })
}

fn scalar_u16(buf: &[u8], off: usize) -> Option<Scalar> {
    let sp = span_at(buf, off, 2)?;
    Some(Scalar {
        value: u16le(&buf[off..off + 2]).to_string(),
        raw: sp.hex.clone(),
        width: 16,
        at: sp,
    })
}

fn scalar_u32(buf: &[u8], off: usize) -> Option<Scalar> {
    let sp = span_at(buf, off, 4)?;
    Some(Scalar {
        value: u32le(&buf[off..off + 4]).to_string(),
        raw: sp.hex.clone(),
        width: 32,
        at: sp,
    })
}

/// Parse a PE byte image. Returns Err only for fatal structural truncation
/// (import rejects the whole batch in that case). Semantic anomalies are
/// reported through [`PeImage::diags`].
pub fn parse(buf: &[u8]) -> Result<PeImage, String> {
    let mut diags = Vec::new();
    if buf.len() < 64 {
        return Err("file shorter than 64 bytes".into());
    }
    if &buf[0..2] != b"MZ" {
        return Err(format!("missing MZ signature, got {:02x}{:02x}", buf[0], buf[1]));
    }
    let e_magic = scalar_u16(buf, 0).ok_or("truncated e_magic")?;
    let e_lfanew = scalar_u32(buf, 0x3c).ok_or("truncated e_lfanew")?;
    let lfanew = u32le(&buf[0x3c..0x40]) as usize;
    let mut fields = Vec::new();
    if let Some(s) = scalar_u16(buf, 2) {
        fields.push(("e_cblp".into(), s));
    }
    if let Some(s) = scalar_u16(buf, 0x18) {
        fields.push(("e_relhdr".into(), s));
    }
    if lfanew + 24 > buf.len() {
        return Err("PE header truncated".into());
    }
    if &buf[lfanew..lfanew + 4] != b"PE\0\0" {
        return Err("missing PE\\0\\0 signature".into());
    }
    let nt_span = span_at(buf, lfanew, 24).unwrap();
    let signature_span = span_at(buf, lfanew, 4).unwrap();
    let coff = lfanew + 4;
    let machine = scalar_u16(buf, coff).unwrap();
    let num_sections = scalar_u16(buf, coff + 2).unwrap();
    let time_date_stamp = scalar_u32(buf, coff + 4).unwrap();
    let characteristics = scalar_u16(buf, coff + 18).unwrap();
    let opt_off = coff + 20;
    let optional_magic = scalar_u16(buf, opt_off).ok_or("truncated optional header magic")?;
    let magic = u16le(&buf[opt_off..opt_off + 2]);
    let pe_class = match magic {
        0x10b => PeClass::Pe32,
        0x20b => PeClass::Pe32Plus,
        other => return Err(format!("unknown optional header magic 0x{other:04x}")),
    };
    let image_base = match pe_class {
        PeClass::Pe32 => scalar_u32(buf, opt_off + 28).ok_or("truncated ImageBase")?,
        PeClass::Pe32Plus => {
            let sp = span_at(buf, opt_off + 24, 8).ok_or("truncated ImageBase")?;
            Scalar {
                value: u64le(&buf[opt_off + 24..opt_off + 32]).to_string(),
                raw: sp.hex.clone(),
                width: 64,
                at: sp,
            }
        }
    };
    let section_alignment = scalar_u32(buf, opt_off + 32).ok_or("truncated SectionAlignment")?;
    let file_alignment = scalar_u32(buf, opt_off + 36).ok_or("truncated FileAlignment")?;
    let size_of_image = scalar_u32(buf, opt_off + 56).ok_or("truncated SizeOfImage")?;
    let size_of_headers = scalar_u32(buf, opt_off + 60).ok_or("truncated SizeOfHeaders")?;
    let num_dirs = u32le(&buf[opt_off + match pe_class {
        PeClass::Pe32 => 92,
        PeClass::Pe32Plus => 108,
    }..opt_off
        + match pe_class {
            PeClass::Pe32 => 96,
            PeClass::Pe32Plus => 112,
        }]) as usize;
    let dir_table_off = opt_off
        + match pe_class {
            PeClass::Pe32 => 96,
            PeClass::Pe32Plus => 112,
        };
    let mut directories = Vec::new();
    for i in 0..num_dirs.min(16) {
        let doff = dir_table_off + i * 8;
        let rva = match scalar_u32(buf, doff) {
            Some(s) => s,
            None => break,
        };
        let size = match scalar_u32(buf, doff + 4) {
            Some(s) => s,
            None => break,
        };
        directories.push(DataDirectory {
            index: i as u8,
            name: DIRECTORY_NAMES[i].to_string(),
            rva,
            size,
        });
    }
    let opt_header_size = u16le(&buf[coff + 16..coff + 18]) as usize;
    let sec_table_off = opt_off + opt_header_size;
    let nsec = u16le(&buf[coff + 2..coff + 4]) as usize;
    let mut sections = Vec::new();
    for i in 0..nsec {
        let sh = sec_table_off + i * 40;
        if sh + 40 > buf.len() {
            diags.push(Diag {
                code: "SECTION_HEADER_TRUNCATED".into(),
                severity: Severity::Error,
                message: format!("section header #{i} runs past EOF"),
                at: None,
            });
            break;
        }
        let raw_name = &buf[sh..sh + 8];
        let end = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&raw_name[..end]).to_string();
        sections.push(SectionHeader {
            name,
            virtual_size: scalar_u32(buf, sh + 8).unwrap(),
            virtual_address: scalar_u32(buf, sh + 12).unwrap(),
            raw_size: scalar_u32(buf, sh + 16).unwrap(),
            raw_pointer: scalar_u32(buf, sh + 20).unwrap(),
            characteristics: scalar_u32(buf, sh + 36).unwrap(),
            header_span: span_at(buf, sh, 40).unwrap(),
        });
    }
    // ---- relocation blocks ------------------------------------------------
    let mut reloc_blocks = Vec::new();
    if let Some(reloc_dir) = directories.iter().find(|d| d.name == "BASERELOC") {
        let dir_rva = u32le(&reloc_dir.rva.at.hex_vec());
        let dir_size = u32le(&reloc_dir.size.at.hex_vec());
        if dir_rva != 0 || dir_size != 0 {
            match walk_relocs(buf, &sections, dir_rva, dir_size, &mut reloc_blocks, &mut diags) {
                Ok(()) => {}
                Err(e) => diags.push(Diag {
                    code: "RELOC_DIRECTORY".into(),
                    severity: Severity::Error,
                    message: e,
                    at: Some(reloc_dir.rva.at.clone()),
                }),
            }
        }
    }

    // ---- import directory -------------------------------------------------
    let mut imports = Vec::new();
    if let Some(import_dir) = directories.iter().find(|d| d.name == "IMPORT") {
        match walk_imports(
            buf,
            &sections,
            import_dir,
            pe_class,
            &mut imports,
            &mut diags,
        ) {
            Ok(()) => {}
            Err(e) => diags.push(Diag {
                code: "IMPORT_DIRECTORY".into(),
                severity: Severity::Error,
                message: e,
                at: Some(import_dir.rva.at.clone()),
            }),
        }
    }

    Ok(PeImage {
        pe_class,
        file_size: buf.len() as u32,
        dos: DosHeader {
            e_magic,
            e_lfanew,
            fields,
        },
        nt_span,
        signature_span,
        machine,
        num_sections,
        time_date_stamp,
        characteristics,
        optional_magic,
        image_base,
        section_alignment,
        file_alignment,
        size_of_image,
        size_of_headers,
        sections,
        directories,
        reloc_blocks,
        imports,
        diags,
    })
}

impl ByteSpan {
    pub fn hex_vec(&self) -> Vec<u8> {
        (0..self.hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&self.hex[i..i + 2], 16).unwrap())
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappingKind {
    Raw,
    ZeroFill,
    Unmapped,
}

#[derive(Debug, Clone)]
pub struct RvaCandidate {
    pub section: Option<String>,
    pub kind: MappingKind,
    pub file_off: Option<u32>,
    pub span: Option<ByteSpan>,
}

/// Enumerate *all* legal raw/zero-fill mappings of an RVA window. Never picks
/// one silently: two sections overlapping the same RVA yield two `Raw`
/// candidates; virtual-only tails yield a single `ZeroFill`; nothing covering
/// yields a single `Unmapped`.
pub fn rva_candidates(buf: &[u8], sections: &[SectionHeader], rva: u32, len: u32) -> Vec<RvaCandidate> {
    let mut out = Vec::new();
    for s in sections {
        let va = u32le(&s.virtual_address.at.hex_vec());
        let vs = u32le(&s.virtual_size.at.hex_vec());
        let rs = u32le(&s.raw_size.at.hex_vec());
        let pr = u32le(&s.raw_pointer.at.hex_vec());
        if rva >= va && rva < va + vs {
            let delta = rva - va;
            if delta < rs {
                let avail = rs - delta;
                let take = len.min(avail);
                let off = pr + delta;
                let sp = span_at(buf, off as usize, take as usize);
                out.push(RvaCandidate {
                    section: Some(s.name.clone()),
                    kind: MappingKind::Raw,
                    file_off: Some(off),
                    span: sp,
                });
            } else {
                out.push(RvaCandidate {
                    section: Some(s.name.clone()),
                    kind: MappingKind::ZeroFill,
                    file_off: None,
                    span: None,
                });
            }
        }
    }
    if out.is_empty() {
        out.push(RvaCandidate {
            section: None,
            kind: MappingKind::Unmapped,
            file_off: None,
            span: None,
        });
    }
    out
}

/// Structured-table reads need bytes. Uses the first Raw candidate but reports
/// overlap / zero-fill / unmapped so nothing is silently collapsed.
fn read_table<'a>(
    buf: &'a [u8],
    sections: &[SectionHeader],
    rva: u32,
    len: u32,
    diags: &mut Vec<Diag>,
    ctx: &str,
) -> Option<Vec<u8>> {
    let cands = rva_candidates(buf, sections, rva, len);
    let raw: Vec<&RvaCandidate> = cands.iter().filter(|c| c.kind == MappingKind::Raw).collect();
    if raw.len() > 1 {
        diags.push(Diag {
            code: "RVA_OVERLAP_READ".into(),
            severity: Severity::Warning,
            message: format!("{ctx}: RVA 0x{rva:08x} raw-backed by {} overlapping sections; using first for table walk, all candidates kept in derived map", raw.len()),
            at: None,
        });
    }
    match raw.first() {
        Some(c) => {
            let sp = c.span.as_ref().unwrap();
            let mut bytes = sp.hex_vec();
            if bytes.len() < len as usize {
                bytes.resize(len as usize, 0);
            }
            Some(bytes)
        }
        None => {
            diags.push(Diag {
                code: "RVA_UNMAPPED_READ".into(),
                severity: Severity::Error,
                message: format!(
                    "{ctx}: RVA 0x{rva:08x} len {} is {}",
                    len,
                    match cands[0].kind {
                        MappingKind::ZeroFill => "zero-fill only",
                        MappingKind::Unmapped => "unmapped",
                        MappingKind::Raw => "raw",
                    }
                ),
                at: None,
            });
            None
        }
    }
}
