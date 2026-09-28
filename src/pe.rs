//! Raw PE parsing. Every extracted value keeps its byte provenance
//! (file offset range inside the source material) and its coordinate
//! basis (file offset vs image RVA). Nothing is normalized away here.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByteRange {
    pub offset: u64, // file offset, bytes
    pub len: u64,    // bytes
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DosHeader {
    pub range: ByteRange,
    pub e_magic: u16,
    pub e_lfanew: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtHeader {
    pub range: ByteRange,
    pub signature: u32,
    pub machine: u16,
    pub number_of_sections: u16,
    pub characteristics: u16,
    pub optional_magic: u16,
    pub image_base: u32,      // preferred base, basis: virtual address
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_dir_offset: u64, // file offset of directory table
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionHeader {
    pub range: ByteRange,
    pub name: String,
    pub virtual_size: u32,    // bytes, basis: image
    pub virtual_address: u32, // RVA, basis: image
    pub raw_size: u32,        // bytes, basis: file
    pub raw_ptr: u32,         // file offset, basis: file
    pub characteristics: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataDirectory {
    pub index: u32,
    pub name: &'static str,
    pub range: ByteRange, // where the directory entry itself lives
    pub rva: u32,         // basis: image
    pub size: u32,        // bytes
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelocEntry {
    pub range: ByteRange, // location of the 2-byte entry
    pub rva: u32,         // target RVA, basis: image
    pub reloc_type: u8,
    pub type_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelocBlock {
    pub range: ByteRange,
    pub page_rva: u32,
    pub block_size: u32,
    pub entries: Vec<RelocEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportThunk {
    pub range: ByteRange,     // INT entry location
    pub iat_range: ByteRange, // matching IAT slot
    pub iat_rva: u32,
    pub dll: String,
    pub by_ordinal: bool,
    pub ordinal: Option<u16>,
    pub hint: Option<u16>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeImage {
    pub dos: DosHeader,
    pub nt: NtHeader,
    pub sections: Vec<SectionHeader>,
    pub directories: Vec<DataDirectory>,
    pub reloc_blocks: Vec<RelocBlock>,
    pub imports: Vec<ImportThunk>,
    pub diagnostics: Vec<ParseDiagnostic>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParseDiagnostic {
    pub code: String,
    pub detail: String,
    pub rva: Option<u32>,
    pub range: Option<ByteRange>,
}

pub const DIR_NAMES: [&str; 16] = [
    "export", "import", "resource", "exception", "certificate", "base_relocation",
    "debug", "architecture", "global_ptr", "tls", "load_config", "bound_import",
    "iat", "delay_import", "clr_runtime", "reserved",
];

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

pub fn parse_pe(bytes: &[u8]) -> Result<PeImage, String> {
    if bytes.len() < 0x40 || u16_at(bytes, 0) != Some(0x5A4D) {
        return Err("missing MZ signature".into());
    }
    let e_lfanew = u32_at(bytes, 0x3C).ok_or("truncated DOS header")?;
    let nt_off = e_lfanew as usize;
    if u32_at(bytes, nt_off) != Some(0x0000_4550) {
        return Err("missing PE\\0\\0 signature".into());
    }
    let coff = nt_off + 4;
    let machine = u16_at(bytes, coff).ok_or("truncated COFF header")?;
    let nsects = u16_at(bytes, coff + 2).ok_or("truncated COFF header")?;
    let opt_size = u16_at(bytes, coff + 16).ok_or("truncated COFF header")? as usize;
    let characteristics = u16_at(bytes, coff + 18).ok_or("truncated COFF header")?;
    let opt = coff + 20;
    let optional_magic = u16_at(bytes, opt).ok_or("truncated optional header")?;
    if optional_magic != 0x10B {
        return Err(format!("unsupported optional header magic 0x{optional_magic:04x} (PE32 only)"));
    }
    let image_base = u32_at(bytes, opt + 28).ok_or("truncated optional header")?;
    let section_alignment = u32_at(bytes, opt + 32).ok_or("truncated optional header")?;
    let file_alignment = u32_at(bytes, opt + 36).ok_or("truncated optional header")?;
    let size_of_image = u32_at(bytes, opt + 56).ok_or("truncated optional header")?;
    let size_of_headers = u32_at(bytes, opt + 60).ok_or("truncated optional header")?;
    let number_of_rva_and_sizes = u32_at(bytes, opt + 92).ok_or("truncated optional header")?;
    let data_dir_offset = (opt + 96) as u64;

    let dos = DosHeader {
        range: ByteRange { offset: 0, len: 0x40 },
        e_magic: 0x5A4D,
        e_lfanew,
    };
    let nt = NtHeader {
        range: ByteRange { offset: nt_off as u64, len: (4 + 20 + opt_size) as u64 },
        signature: 0x4550,
        machine,
        number_of_sections: nsects,
        characteristics,
        optional_magic,
        image_base,
        section_alignment,
        file_alignment,
        size_of_image,
        size_of_headers,
        number_of_rva_and_sizes,
        data_dir_offset,
    };

    let sect_table = opt + opt_size;
    let mut sections = Vec::new();
    for i in 0..nsects as usize {
        let base = sect_table + i * 40;
        let name_bytes = bytes.get(base..base + 8).ok_or("truncated section table")?;
        let name = String::from_utf8_lossy(
            &name_bytes[..name_bytes.iter().position(|&c| c == 0).unwrap_or(8)],
        )
        .to_string();
        sections.push(SectionHeader {
            range: ByteRange { offset: base as u64, len: 40 },
            name,
            virtual_size: u32_at(bytes, base + 8).ok_or("truncated section")?,
            virtual_address: u32_at(bytes, base + 12).ok_or("truncated section")?,
            raw_size: u32_at(bytes, base + 16).ok_or("truncated section")?,
            raw_ptr: u32_at(bytes, base + 20).ok_or("truncated section")?,
            characteristics: u32_at(bytes, base + 36).ok_or("truncated section")?,
        });
    }

    let mut directories = Vec::new();
    let ndirs = number_of_rva_and_sizes.min(16) as usize;
    for i in 0..ndirs {
        let base = data_dir_offset as usize + i * 8;
        if let (Some(rva), Some(size)) = (u32_at(bytes, base), u32_at(bytes, base + 4)) {
            directories.push(DataDirectory {
                index: i as u32,
                name: DIR_NAMES[i],
                range: ByteRange { offset: base as u64, len: 8 },
                rva,
                size,
            });
        }
    }

    let mut diagnostics = Vec::new();
    let mut reloc_blocks = Vec::new();
    let mut imports = Vec::new();

    // Validate each directory range against the image; a corrupt directory
    // only disables that directory, everything else still parses.
    for dir in &directories {
        if dir.rva == 0 || dir.size == 0 {
            continue;
        }
        let end = dir.rva as u64 + dir.size as u64;
        if end > size_of_image as u64 {
            diagnostics.push(ParseDiagnostic {
                code: "corrupt_directory_range".into(),
                detail: format!(
                    "directory {} rva=0x{:x} size=0x{:x} exceeds SizeOfImage 0x{:x}",
                    dir.name, dir.rva, dir.size, size_of_image
                ),
                rva: Some(dir.rva),
                range: Some(dir.range.clone()),
            });
            continue;
        }
        match dir.name {
            "base_relocation" => parse_relocs(bytes, dir, &sections, &nt, &mut reloc_blocks, &mut diagnostics),
            "import" => parse_imports(bytes, dir, &sections, &nt, &mut imports, &mut diagnostics),
            _ => {}
        }
    }

    Ok(PeImage { dos, nt, sections, directories, reloc_blocks, imports, diagnostics })
}

/// Map an RVA to a file offset using the first matching section's raw range.
/// Returns None when the RVA has no raw backing (headers, zero-fill, unmapped).
pub fn rva_to_file_offset_first(
    sections: &[SectionHeader],
    size_of_headers: u32,
    rva: u32,
) -> Option<u32> {
    if rva < size_of_headers {
        return Some(rva);
    }
    for s in sections {
        let span = s.virtual_size.max(s.raw_size);
        if rva >= s.virtual_address && rva < s.virtual_address + span && rva - s.virtual_address < s.raw_size {
            return Some(s.raw_ptr + (rva - s.virtual_address));
        }
    }
    None
}

fn parse_relocs(
    bytes: &[u8],
    dir: &DataDirectory,
    sections: &[SectionHeader],
    nt: &NtHeader,
    out: &mut Vec<RelocBlock>,
    diags: &mut Vec<ParseDiagnostic>,
) {
    let mut cursor = dir.rva;
    let end = dir.rva + dir.size;
    while cursor + 8 <= end {
        let Some(off) = rva_to_file_offset_first(sections, nt.size_of_headers, cursor) else {
            diags.push(ParseDiagnostic {
                code: "reloc_block_unmapped".into(),
                detail: format!("relocation block header RVA 0x{cursor:x} has no file mapping"),
                rva: Some(cursor),
                range: None,
            });
            return;
        };
        let off = off as usize;
        let (Some(page_rva), Some(block_size)) = (u32_at(bytes, off), u32_at(bytes, off + 4)) else {
            return;
        };
        if block_size < 8 || cursor + block_size > end {
            diags.push(ParseDiagnostic {
                code: "reloc_block_truncated".into(),
                detail: format!("block at RVA 0x{cursor:x} size 0x{block_size:x} exceeds directory"),
                rva: Some(cursor),
                range: None,
            });
            return;
        }
        let mut entries = Vec::new();
        let n = (block_size - 8) / 2;
        for i in 0..n {
            let eoff = off + 8 + i as usize * 2;
            let Some(raw) = u16_at(bytes, eoff) else { break };
            let reloc_type = (raw >> 12) as u8;
            let low = raw & 0x0FFF;
            let type_name = match reloc_type {
                0 => "ABSOLUTE",
                1 => "HIGH",
                2 => "LOW",
                3 => "HIGHLOW",
                4 => "HIGHADJ",
                10 => "DIR64",
                other => {
                    entries.push(RelocEntry {
                        range: ByteRange { offset: eoff as u64, len: 2 },
                        rva: page_rva + low as u32,
                        reloc_type,
                        type_name: format!("UNKNOWN({other})"),
                    });
                    continue;
                }
            };
            entries.push(RelocEntry {
                range: ByteRange { offset: eoff as u64, len: 2 },
                rva: page_rva + low as u32,
                reloc_type,
                type_name: type_name.to_string(),
            });
        }
        out.push(RelocBlock {
            range: ByteRange { offset: off as u64, len: block_size as u64 },
            page_rva,
            block_size,
            entries,
        });
        cursor += block_size;
    }
}

fn parse_imports(
    bytes: &[u8],
    dir: &DataDirectory,
    sections: &[SectionHeader],
    nt: &NtHeader,
    out: &mut Vec<ImportThunk>,
    diags: &mut Vec<ParseDiagnostic>,
) {
    let map = |rva: u32| rva_to_file_offset_first(sections, nt.size_of_headers, rva).map(|v| v as usize);
    let mut desc_rva = dir.rva;
    loop {
        let Some(doff) = map(desc_rva) else {
            diags.push(ParseDiagnostic {
                code: "import_descriptor_unmapped".into(),
                detail: format!("import descriptor RVA 0x{desc_rva:x} has no file mapping"),
                rva: Some(desc_rva),
                range: None,
            });
            return;
        };
        let (Some(oft), Some(_time), Some(_chain), Some(name_rva), Some(ft)) = (
            u32_at(bytes, doff),
            u32_at(bytes, doff + 4),
            u32_at(bytes, doff + 8),
            u32_at(bytes, doff + 12),
            u32_at(bytes, doff + 16),
        ) else {
            return;
        };
        if oft == 0 && name_rva == 0 && ft == 0 {
            return; // null descriptor terminates the table
        }
        let dll = map(name_rva)
            .and_then(|o| read_cstr(bytes, o))
            .unwrap_or_else(|| format!("<unmapped name @0x{name_rva:x}>"));
        let int_rva = if oft != 0 { oft } else { ft };
        let mut i = 0u32;
        loop {
            let thunk_rva = int_rva + i * 4;
            let Some(toff) = map(thunk_rva) else { break };
            let Some(val) = u32_at(bytes, toff) else { break };
            if val == 0 {
                break;
            }
            let iat_rva = ft + i * 4;
            let iat_off = map(iat_rva).unwrap_or(0);
            if val & 0x8000_0000 != 0 {
                out.push(ImportThunk {
                    range: ByteRange { offset: toff as u64, len: 4 },
                    iat_range: ByteRange { offset: iat_off as u64, len: 4 },
                    iat_rva,
                    dll: dll.clone(),
                    by_ordinal: true,
                    ordinal: Some((val & 0xFFFF) as u16),
                    hint: None,
                    name: None,
                });
            } else {
                let (hint, name) = map(val)
                    .and_then(|o| {
                        u16_at(bytes, o).and_then(|h| read_cstr(bytes, o + 2).map(|n| (h, n)))
                    })
                    .unwrap_or((0, format!("<unmapped hint/name @0x{val:x}>")));
                out.push(ImportThunk {
                    range: ByteRange { offset: toff as u64, len: 4 },
                    iat_range: ByteRange { offset: iat_off as u64, len: 4 },
                    iat_rva,
                    dll: dll.clone(),
                    by_ordinal: false,
                    ordinal: None,
                    hint: Some(hint),
                    name: Some(name),
                });
            }
            i += 1;
        }
        desc_rva += 20;
    }
}

fn read_cstr(bytes: &[u8], off: usize) -> Option<String> {
    let tail = bytes.get(off..)?;
    let end = tail.iter().position(|&c| c == 0)?;
    Some(String::from_utf8_lossy(&tail[..end]).to_string())
}
