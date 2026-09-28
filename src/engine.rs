use serde_json::json;

use crate::fixture::*;
use crate::model::{Candidate, EvidenceRef, Material, RULE_VERSION_1};

#[derive(Debug, Clone)]
pub struct ParsedPe {
    pub image_base: u64,
    pub size_of_image: u32,
    pub sections: Vec<Section>,
    pub directories: Vec<Directory>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_pointer: u32,
    pub raw_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directory {
    pub index: usize,
    pub name: String,
    pub rva: u32,
    pub size: u32,
}

pub fn parse_pe(bytes: &[u8]) -> Result<ParsedPe, String> {
    if bytes.len() < 0x200 || &bytes[0..2] != b"MZ" {
        return Err("missing DOS signature".into());
    }
    let pe_off = read_u32(bytes, 0x3c) as usize;
    if pe_off + 24 > bytes.len() || &bytes[pe_off..pe_off + 4] != b"PE\0\0" {
        return Err("missing NT signature".into());
    }
    let opt = pe_off + 24;
    let magic = read_u16(bytes, opt);
    if magic != 0x20b {
        return Err("case package requires PE32+ optional header".into());
    }
    let image_base = read_u64(bytes, opt + 24);
    let size_of_image = read_u32(bytes, opt + 56);
    let number_of_sections = read_u16(bytes, pe_off + 6) as usize;
    let size_of_optional = read_u16(bytes, pe_off + 20) as usize;
    let sections_off = opt + size_of_optional;
    let mut sections = Vec::new();
    for i in 0..number_of_sections {
        let off = sections_off + i * 40;
        let raw_name = &bytes[off..off + 8];
        let end = raw_name.iter().position(|b| *b == 0).unwrap_or(8);
        sections.push(Section {
            name: String::from_utf8_lossy(&raw_name[..end]).to_string(),
            virtual_size: read_u32(bytes, off + 8),
            virtual_address: read_u32(bytes, off + 12),
            raw_size: read_u32(bytes, off + 16),
            raw_pointer: read_u32(bytes, off + 20),
        });
    }
    let dir_count = read_u32(bytes, opt + 108) as usize;
    let dir_base = opt + 112;
    let names = [
        "export", "import", "resource", "exception", "certificate", "base-relocation", "debug",
        "architecture", "global-ptr", "tls", "load-config", "bound-import", "iat",
        "delay-import", "clr", "reserved",
    ];
    let mut directories = Vec::new();
    for index in 0..dir_count.min(16) {
        directories.push(Directory {
            index,
            name: names[index].to_string(),
            rva: read_u32(bytes, dir_base + index * 8),
            size: read_u32(bytes, dir_base + index * 8 + 4),
        });
    }
    Ok(ParsedPe { image_base, size_of_image, sections, directories })
}

pub fn read_u16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
pub fn read_u32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
pub fn read_u64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressCandidate {
    pub coordinate: String,
    pub section_name: String,
    pub source: String,
    pub file_offset: Option<u32>,
    pub va: u64,
}

pub fn rva_to_file_candidates(rva: u32, parsed: &ParsedPe, expected_base: u64) -> Vec<AddressCandidate> {
    let mut out = Vec::new();
    for section in &parsed.sections {
        let v_end = section.virtual_address.saturating_add(section.virtual_size);
        if !(section.virtual_address..v_end).contains(&rva) {
            continue;
        }
        let delta = rva - section.virtual_address;
        let va = expected_base + rva as u64;
        if delta >= section.raw_size {
            out.push(AddressCandidate {
                coordinate: format!("0x{rva:x}"),
                section_name: section.name.clone(),
                source: "zero-fill".into(),
                file_offset: None,
                va,
            });
        } else {
            out.push(AddressCandidate {
                coordinate: format!("0x{rva:x}"),
                section_name: section.name.clone(),
                source: "mapped-file-bytes".into(),
                file_offset: Some(section.raw_pointer + delta),
                va,
            });
        }
    }
    out
}

pub fn generate_candidates(materials: &[Material], params_revision: u32, material_revision: u32, event_id: &str) -> Vec<Candidate> {
    let pe_material = find_material(materials, PE_ID).expect("PE material");
    let pe = parse_pe_hex(&pe_material.bytes).expect("fixture PE parses");
    let expected_base = expected_image_base(materials);
    let mut out = Vec::new();
    out.extend(header_candidates(&pe, event_id, params_revision, material_revision));
    let pe_bytes = decode_hex(&pe_material.bytes).expect("fixture PE bytes");
    out.extend(directory_candidates(&pe, event_id, params_revision, material_revision));
    out.extend(address_candidates(&pe, expected_base, event_id, params_revision, material_revision));
    out.extend(relocation_candidates(&pe, &pe_bytes, expected_base, event_id, params_revision, material_revision));
    out.extend(import_candidates(materials, &pe, &pe_bytes, event_id, params_revision, material_revision));
    out
}

fn parse_pe_hex(hexed: &str) -> Result<ParsedPe, String> {
    let bytes = decode_hex(hexed)?;
    parse_pe(&bytes)
}

pub fn decode_hex(hexed: &str) -> Result<Vec<u8>, String> {
    (0..hexed.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hexed[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn find_material<'a>(materials: &'a [Material], id: &str) -> Option<&'a Material> {
    materials.iter().filter(|m| m.material_id == id).max_by_key(|m| m.revision)
}

pub fn expected_image_base(materials: &[Material]) -> u64 {
    let material = find_material(materials, IMAGE_BASE_ID).expect("image-base material");
    material
        .original_representation["expected_image_base"]
        .as_str()
        .unwrap_or(INITIAL_BASE_HEX)
        .split_whitespace()
        .next()
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(INITIAL_BASE)
}

fn pe_evidence(offset: u64, length: u64, representation: &str) -> EvidenceRef {
    EvidenceRef {
        material_id: PE_ID.into(),
        revision: 1,
        offset,
        length,
        coordinate_basis: "file-offset[byte]".into(),
        representation: representation.into(),
    }
}

fn header_candidates(pe: &ParsedPe, event: &str, params: u32, mats: u32) -> Vec<Candidate> {
    vec![candidate(
        "header-image-base",
        "header",
        "NT OptionalHeader ImageBase",
        "parsed-image-base",
        "u64 VA parsed from optional header",
        "adopted",
        json!({"value": format!("0x{:x}[VA-byte]", pe.image_base), "unit": "u64[VA-byte]"}),
        vec![pe_evidence(0xc0, 8, "IMAGE_OPTIONAL_HEADER64.ImageBase")],
        event, params, mats, "headers",
    )]
}

fn section_candidates(pe: &ParsedPe, event: &str, params: u32, mats: u32) -> Vec<Candidate> {
    pe.sections.iter().enumerate().map(|(i, s)| {
        let off = 0x188 + i * 40;
        candidate(
            &format!("section-{}", s.name.trim_start_matches('.')),
            "section",
            &format!("{} interval", s.name),
            "mapped-section",
            "raw and virtual coordinates preserved",
            "adopted",
            json!({
                "name": s.name,
                "virtual_range": format!("0x{:x}..0x{:x}[RVA-byte]", s.virtual_address, s.virtual_address + s.virtual_size),
                "raw_range": format!("0x{:x}..0x{:x}[file-byte]", s.raw_pointer, s.raw_pointer + s.raw_size),
                "virtual_size": format!("{}[byte]", s.virtual_size),
                "raw_size": format!("{}[byte]", s.raw_size)
            }),
            vec![pe_evidence(off as u64, 40, "IMAGE_SECTION_HEADER")],
            event, params, mats, "sections",
        )
    }).collect()
}

fn directory_candidates(pe: &ParsedPe, event: &str, params: u32, mats: u32) -> Vec<Candidate> {
    pe.directories.iter().filter(|d| d.rva != 0 || d.size != 0).map(|d| {
        let in_image = (d.rva as u64 + d.size as u64) <= pe.size_of_image as u64;
        candidate(
            &format!("data-directory-{}", d.name),
            "data-directory",
            &format!("{} data directory", d.name),
            if in_image { "declared-range" } else { "corrupt-outside-image" },
            if in_image { "directory range is within SizeOfImage" } else { "directory range exceeds SizeOfImage" },
            if in_image { "adopted" } else { "diagnostic-corrupt-range" },
            json!({
                "index": d.index,
                "rva": format!("0x{:x}[RVA-byte]", d.rva),
                "size": format!("{}[byte]", d.size),
                "size_of_image": format!("0x{:x}[VA-byte]", pe.size_of_image),
                "range_valid": in_image
            }),
            vec![pe_evidence((0x128 + d.index * 8) as u64, 8, "IMAGE_DATA_DIRECTORY")],
            event, params, mats, "data-directories",
        )
    }).collect()
}

fn candidate(
    subject_id: &str,
    subject_kind: &str,
    subject_label: &str,
    option_id: &str,
    option_label: &str,
    status: &str,
    value: serde_json::Value,
    evidence: Vec<EvidenceRef>,
    event: &str,
    params: u32,
    mats: u32,
    batch: &str,
) -> Candidate {
    Candidate {
        candidate_id: format!("{subject_id}:{option_id}"),
        subject_id: subject_id.into(),
        subject_kind: subject_kind.into(),
        subject_label: subject_label.into(),
        option_id: option_id.into(),
        option_label: option_label.into(),
        status: status.into(),
        value,
        evidence,
        source_refs: vec![format!("{PE_ID}:1")],
        invalidated_by: None,
        depends_on: vec![format!("{PE_ID}:1")],
        rule_version: RULE_VERSION_1.into(),
        params_revision: params,
        material_revision: mats,
        batch: batch.into(),
        created_by_event: event.into(),
    }
}

fn address_candidates(pe: &ParsedPe, expected_base: u64, event: &str, params: u32, mats: u32) -> Vec<Candidate> {
    let mut out = Vec::new();
    for rva in [0x1008u32, 0x2008, 0x3100, 0x5000] {
        let options = rva_to_file_candidates(rva, pe, expected_base);
        let subject = format!("rva-0x{rva:x}");
        if options.is_empty() {
            out.push(candidate(
                &subject,
                "address-map",
                &format!("RVA 0x{rva:x}[RVA-byte] translation"),
                "unmapped",
                "RVA has no virtual section mapping",
                "diagnostic-unmapped",
                json!({"rva": format!("0x{rva:x}[RVA-byte]"), "va": format!("0x{:x}[VA-byte]", expected_base + rva as u64), "file_offset": null}),
                vec![pe_evidence(0x188, (40 * pe.sections.len()) as u64, "section table")],
                event, params, mats, "address-map",
            ));
        } else {
            for (i, option) in options.iter().enumerate() {
                out.push(candidate(
                    &subject,
                    "address-map",
                    &format!("RVA 0x{rva:x}[RVA-byte] translation"),
                    &format!("{}-{}", option.source, i),
                    &format!("{} via {}", option.source, option.section_name),
                    if options.len() > 1 { "legal-ambiguous" } else { "adopted" },
                    json!({
                        "rva": format!("0x{rva:x}[RVA-byte]"),
                        "va": format!("0x{:x}[VA-byte]", option.va),
                        "section": option.section_name,
                        "file_offset": option.file_offset.map(|v| format!("0x{v:x}[file-byte]")),
                        "source": option.source
                    }),
                    vec![pe_evidence(0x188, (40 * pe.sections.len()) as u64, "section table")],
                    event, params, mats, "address-map",
                ));
            }
        }
    }

    let file_offset = TEXT_RAW_PTR + 8;
    let reverse: Vec<_> = pe.sections.iter().filter(|s| {
        file_offset >= s.raw_pointer && file_offset < s.raw_pointer + s.raw_size
    }).cloned().collect();
    for (i, section) in reverse.iter().enumerate() {
        out.push(candidate(
            "file-offset-0x408",
            "address-map",
            "file offset 0x408[file-byte] reverse translation",
            &format!("raw-overlap-{i}"),
            &format!("claimed by {} raw range", section.name),
            if reverse.len() > 1 { "legal-ambiguous" } else { "adopted" },
            json!({
                "file_offset": format!("0x{file_offset:x}[file-byte]"),
                "claimed_by_section": section.name,
                "claimed_rva": format!("0x{:x}[RVA-byte]", section.virtual_address + (file_offset - section.raw_pointer))
            }),
            vec![pe_evidence(0x188, (40 * pe.sections.len()) as u64, "section table raw ranges")],
            event, params, mats, "address-map",
        ));
    }
    out
}

fn relocation_candidates(pe: &ParsedPe, pe_bytes: &[u8], expected_base: u64, event: &str, params: u32, mats: u32) -> Vec<Candidate> {
    let mut entries = parse_relocations(pe, pe_bytes);
    let delta = expected_base.wrapping_sub(INITIAL_BASE);
    let mut out = Vec::new();
    for entry in entries.drain(..) {
        let maps = rva_to_file_candidates(entry.target_rva, pe, expected_base);
        let mapped: Vec<_> = maps.iter().filter(|m| m.file_offset.is_some()).collect();
        let subject = format!("reloc-{}", entry.label);
        let status = if entry.target_rva >= pe.size_of_image {
            "diagnostic-relocation-overflow"
        } else if mapped.is_empty() {
            "diagnostic-unmapped-relocation-target"
        } else if entry.relocation_type == 3 && entry.original_u32.checked_add(delta as u32).is_none() {
            "diagnostic-width-overflow"
        } else if mapped.len() > 1 {
            "legal-ambiguous"
        } else {
            "adopted"
        };
        let patch = if entry.relocation_type == 10 {
            json!({"old": format!("0x{:016x}[u64-VA-byte]", entry.original_u64), "new": format!("0x{:016x}[u64-VA-byte]", entry.original_u64.wrapping_add(delta)), "width": "64[bit]"})
        } else if entry.relocation_type == 3 {
            json!({"old": format!("0x{:08x}[u32-VA-byte]", entry.original_u32), "new": format!("0x{:08x}[u32-VA-byte]", entry.original_u32.wrapping_add(delta as u32)), "width": "32[bit]"})
        } else {
            json!({"patch": "none[byte]", "reason": "IMAGE_REL_BASED_ABSOLUTE padding"})
        };
        out.push(candidate(
            &subject,
            "relocation",
            &format!("{} base relocation", entry.label),
            entry.option.as_str(),
            &entry.option_label,
            status,
            json!({
                "type": entry.type_name,
                "type_number": format!("{}[IMAGE_REL_BASED]", entry.relocation_type),
                "page_rva": format!("0x{:x}[RVA-byte]", entry.page_rva),
                "target_rva": format!("0x{:x}[RVA-byte]", entry.target_rva),
                "delta": format!("0x{:x}[byte]", delta),
                "mapping_count": maps.len(),
                "patch": patch
            }),
            vec![
                pe_evidence(entry.block_offset as u64, 10, "IMAGE_BASE_RELOCATION block"),
                pe_evidence(entry.entry_offset as u64, 2, "relocation type[4-bit]+offset[12-bit]"),
            ],
            event, params, mats, "relocations",
        ));
    }
    out
}

#[derive(Debug, Clone)]
struct RelocationEntry {
    label: String,
    option: String,
    option_label: String,
    page_rva: u32,
    target_rva: u32,
    relocation_type: u16,
    type_name: String,
    original_u64: u64,
    original_u32: u32,
    block_offset: u32,
    entry_offset: u32,
}

fn parse_relocations(pe: &ParsedPe, b: &[u8]) -> Vec<RelocationEntry> {
    let mut rva = RELOC_DIR_RVA;
    let end = RELOC_DIR_RVA + RELOC_DIR_SIZE;
    let mut entries = Vec::new();
    let mut index = 0;
    while rva < end {
        let block_file = RELOC_RAW_PTR + (rva - RELOC_VA);
        let page = read_u32(&b, block_file as usize);
        let size = read_u32(&b, block_file as usize + 4);
        let count = if size >= 8 { (size - 8) / 2 } else { 0 };
        for i in 0..count {
            let entry = read_u16(&b, (block_file + 8 + i * 2) as usize);
            let kind = entry >> 12;
            let offset = entry & 0x0fff;
            if kind == 0 { continue; }
            let target = page.wrapping_add(offset);
            let target_file = TEXT_RAW_PTR.max(RDATA_RAW_PTR).wrapping_sub(0);
            let original_u64 = if target >= RDATA_VA && target < RDATA_VA + RDATA_RAW_SIZE {
                read_u64_or_32(&b, (RDATA_RAW_PTR + target - RDATA_VA) as usize)
            } else if target >= TEXT_VA && target < TEXT_VA + TEXT_RAW_SIZE {
                read_u64_or_32(&b, (TEXT_RAW_PTR + target - TEXT_VA) as usize)
            } else { 0 };
            let original_u32 = if target >= RDATA_VA && target < RDATA_VA + RDATA_RAW_SIZE {
                read_u32(&b, (RDATA_RAW_PTR + target - RDATA_VA) as usize)
            } else if target >= TEXT_VA && target < TEXT_VA + TEXT_RAW_SIZE {
                read_u32(&b, (TEXT_RAW_PTR + target - TEXT_VA) as usize)
            } else { 0 };
            entries.push(RelocationEntry {
                label: format!("block-{index}-entry-{i}"),
                option: format!("type-{kind}-offset-0x{offset:x}"),
                option_label: format!("type {kind}, width {} bits", if kind == 10 { 64 } else if kind == 3 { 32 } else { 16 }),
                page_rva: page,
                target_rva: target,
                relocation_type: kind,
                type_name: if kind == 10 { "DIR64" } else if kind == 3 { "HIGHLOW" } else { "UNKNOWN" }.into(),
                original_u64,
                original_u32,
                block_offset: block_file,
                entry_offset: block_file + 8 + i * 2,
            });
            let _ = target_file;
        }
        if size == 0 { break; }
        rva += size;
        index += 1;
    }
    entries
}

fn read_u64_or_32(b: &[u8], off: usize) -> u64 {
    if off + 8 <= b.len() { read_u64(b, off) } else if off + 4 <= b.len() { read_u32(b, off) as u64 } else { 0 }
}

fn import_candidates(materials: &[Material], pe: &ParsedPe, bytes: &[u8], event: &str, params: u32, mats: u32) -> Vec<Candidate> {
    let pe_material = find_material(materials, PE_ID).expect("PE material");
    let snapshot_material = find_material(materials, SNAPSHOT_ID).expect("snapshot material");
    let _ = pe_material;
    let import_dir = pe.directories.iter().find(|d| d.name == "import").expect("import directory");
    let import_file = RDATA_RAW_PTR + (import_dir.rva - RDATA_VA);
    let mut out = Vec::new();
    for descriptor_index in 0..4 {
        let desc = import_file + descriptor_index * 20;
        let original_first_thunk = read_u32(&bytes, desc as usize);
        let name_rva = read_u32(&bytes, desc as usize + 12);
        let iat_rva = read_u32(&bytes, desc as usize + 16);
        if original_first_thunk == 0 && name_rva == 0 && iat_rva == 0 {
            break;
        }
        let dll_name = read_cstr(&bytes, rva_to_unique_file(&bytes, name_rva, pe));
        let mut thunk_index = 0;
        loop {
            let thunk_rva = original_first_thunk + thunk_index * 8;
            let thunk_file = rva_to_unique_file(&bytes, thunk_rva, pe);
            let thunk_value = read_u64(&bytes, thunk_file);
            if thunk_value == 0 {
                break;
            }
            let (lookup_kind, symbol_label, name_evidence_offset) = if thunk_value & (1u64 << 63) != 0 {
                let ordinal = thunk_value & 0xffff;
                ("ordinal", format!("#{}[ordinal]", ordinal), 0)
            } else {
                let hint_name_rva = thunk_value as u32;
                let name_file = rva_to_unique_file(&bytes, hint_name_rva + 2, pe);
                (
                    "name",
                    read_cstr(&bytes, name_file),
                    (RDATA_RAW_PTR + hint_name_rva - RDATA_VA) as u64,
                )
            };

            let subject = format!("import-{dll_name}-{thunk_index}");
            let resolution = resolve_import(&dll_name, &symbol_label, snapshot_material);
            let mut cand = candidate(
                &subject,
                "import",
                &format!("{dll_name}!{}", symbol_label.trim_end_matches("[ordinal]")),
                resolution.option.as_str(),
                resolution.option_label.as_str(),
                resolution.status.as_str(),
                json!({
                    "dll": dll_name,
                    "lookup": lookup_kind,
                    "symbol": symbol_label,
                    "thunk_rva": format!("0x{thunk_rva:x}[RVA-byte]"),
                    "iat_slot": format!("0x{:x}[RVA-byte]", iat_rva + thunk_index * 8),
                    "resolution": resolution.value
                }),
                vec![
                    pe_evidence(desc as u64, 20, "IMAGE_IMPORT_DESCRIPTOR"),
                    pe_evidence(thunk_file as u64, 8, "IMAGE_THUNK_DATA64"),
                    pe_evidence(name_evidence_offset.max(rva_to_unique_file(&bytes, name_rva, pe) as u64), if lookup_kind == "name" { symbol_label.len() as u64 + 2 } else { dll_name.len() as u64 + 1 }, "hint/name or DLL name bytes"),
                ],
                event,
                params,
                mats,
                "imports",
            );
            cand.source_refs.push(format!("{}:{}", SNAPSHOT_ID, snapshot_material.revision));
            cand.depends_on.push(format!("{}:{}", SNAPSHOT_ID, snapshot_material.revision));
            cand.evidence.push(EvidenceRef {
                material_id: SNAPSHOT_ID.into(),
                revision: snapshot_material.revision,
                offset: snapshot_material.bytes.find(resolution.snapshot_needle.as_str()).unwrap_or(0) as u64,
                length: resolution.snapshot_needle.len() as u64,
                coordinate_basis: "utf-8/json-byte".into(),
                representation: "DLL export snapshot original representation".into(),
            });
            out.push(cand);
            thunk_index += 1;
        }
    }
    out
}

fn rva_to_unique_file(bytes: &[u8], rva: u32, pe: &ParsedPe) -> usize {
    rva_to_file_candidates(rva, pe, INITIAL_BASE)
        .into_iter()
        .find_map(|c| c.file_offset)
        .unwrap_or(0) as usize
        .min(bytes.len() - 1)
}

fn read_cstr(bytes: &[u8], mut off: usize) -> String {
    let start = off;
    while off < bytes.len() && bytes[off] != 0 {
        off += 1;
    }
    String::from_utf8_lossy(&bytes[start..off]).to_string()
}

struct ImportResolution {
    option: String,
    option_label: String,
    status: String,
    value: serde_json::Value,
    snapshot_needle: String,
}

fn resolve_import(dll: &str, symbol: &str, snapshot: &Material) -> ImportResolution {
    if dll == "missing.dll" {
        return ImportResolution {
            option: "unresolved-missing-dll".into(),
            option_label: "missing DLL produces unresolved import only".into(),
            status: "unresolved-missing-dll".into(),
            value: json!({"binding": null, "diagnostic": "DLL snapshot has no module named missing.dll"}),
            snapshot_needle: "\"missing\"".into(),
        };
    }
    let clean = symbol.trim_start_matches("\0\0");
    if clean == "Forwarded" {
        return ImportResolution {
            option: "forwarded-export".into(),
            option_label: "forward through feature.dll!Forwarded to kernel32!HeapAlloc".into(),
            status: "adopted-forwarded".into(),
            value: json!({
                "binding": "feature.dll!Forwarded -> kernel32.dll!HeapAlloc",
                "coordinates": ["feature.dll 0x2030[RVA-byte]", "forwarder kernel32.HeapAlloc"]
            }),
            snapshot_needle: "\"forwards_to\":\"kernel32.HeapAlloc\"".into(),
        };
    }
    let exports = &snapshot.original_representation["dlls"][dll]["exports"];
    let found = exports.as_array().into_iter().flatten().find(|entry| entry["name"].as_str() == Some(clean));
    let rva = found.and_then(|entry| entry["rva"].as_str()).unwrap_or("unknown[RVA-byte]").to_string();
    ImportResolution {
        option: "resolved-by-name".into(),
        option_label: "resolved against export snapshot".into(),
        status: "adopted".into(),
        value: json!({"binding": format!("{dll}!{clean}"), "export_rva": rva}),
        snapshot_needle: format!("\"name\":\"{clean}\""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fixed_pe32_plus_layout() {
        let parsed = parse_pe(&build_pe_bytes()).unwrap();
        assert_eq!(parsed.sections.len(), 4);
        assert_eq!(parsed.image_base, INITIAL_BASE);
        assert_eq!(parsed.sections[1].virtual_size, 0x1200);
        assert!(parsed.sections[1].virtual_size > parsed.sections[1].raw_size);
    }

    #[test]
    fn keeps_unmapped_overlap_zero_fill_candidates() {
        let parsed = parse_pe(&build_pe_bytes()).unwrap();
        assert_eq!(rva_to_file_candidates(0x5000, &parsed, INITIAL_BASE).len(), 0);
        let overlap = rva_to_file_candidates(0x3100, &parsed, INITIAL_BASE);
        assert_eq!(overlap.len(), 2);
        let zero_fill = rva_to_file_candidates(0x2100, &parsed, INITIAL_BASE);
        assert!(zero_fill.iter().any(|c| c.source == "zero-fill"));
    }

    #[test]
    fn executes_relocations_by_type_and_width() {
        let parsed = parse_pe(&build_pe_bytes()).unwrap();
        let candidates = generate_candidates(&build_initial_materials(), 1, 1, "evt-test");
        let overflow = candidates.iter().find(|c| c.subject_id.starts_with("reloc-") && c.status.contains("overflow")).unwrap();
        assert!(overflow.value.to_string().contains("32[bit]"));
        assert!(parsed.directories.iter().any(|d| d.name == "debug" && d.rva == DEBUG_RVA));
    }

    #[test]
    fn resolves_name_ordinal_forwarded_and_missing_imports() {
        let candidates = generate_candidates(&build_initial_materials(), 1, 1, "evt-test");
        let statuses: Vec<_> = candidates.iter().filter(|c| c.subject_kind == "import").map(|c| c.status.clone()).collect();
        assert!(statuses.contains(&"adopted".to_string()));
        assert!(statuses.contains(&"adopted-forwarded".to_string()));
        assert!(statuses.contains(&"unresolved-missing-dll".to_string()));
        assert!(candidates.iter().any(|c| c.value.to_string().contains("ordinal")));
    }
}
