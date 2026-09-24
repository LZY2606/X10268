//! Deterministic, lossless PE structural parser.
//!
//! It never irreversibly cleans input: unreadable / ambiguous structures are
//! kept with diagnostics. Raw bytes and spans are retained for every field.

use crate::core::*;
use crate::ids::stable_id;
use crate::mapper::{self, OriginKind};

const DIR_LABELS: [&str; 16] = [
    "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "CERTIFICATE", "BASERELOC",
    "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT",
    "IAT", "DELAY_IMPORT", "CLR", "RESERVED",
];

struct Ctx<'a> {
    pe: &'a [u8],
    mid: String,
    ord: u32,
    diags: Vec<Diag>,
}

impl<'a> Ctx<'a> {
    fn span(&self, off: u64, len: u64) -> Span {
        Span { material_id: self.mid.clone(), file_offset: off, length: len }
    }
    fn diag(&mut self, code: &str, sev: DiagSeverity, msg: impl Into<String>,
            span: Option<Span>, rva: Option<Q>, obj: Option<String>) {
        self.diags.push(Diag {
            code: code.into(), severity: sev, message: msg.into(),
            span, rva, object_id: obj,
        });
    }
    fn next_ord(&mut self) -> u32 {
        let v = self.ord;
        self.ord += 1;
        v
    }
}

fn rd16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn rd32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn rd64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes([
        b[o], b[o + 1], b[o + 2], b[o + 3],
        b[o + 4], b[o + 5], b[o + 6], b[o + 7],
    ])
}
fn hexof(b: &[u8]) -> String {
    hex::encode(b)
}

pub fn parse(pe: &[u8], material_id: &str) -> PeFacts {
    let mut facts = PeFacts {
        pe_material_id: material_id.into(),
        ..Default::default()
    };
    let mut ctx = Ctx { pe, mid: material_id.into(), ord: 0, diags: Vec::new() };

    // ---- DOS header ----
    let mut dos_fields = Vec::new();
    if pe.len() < 0x40 {
        ctx.diag("dos_header_truncated", DiagSeverity::Error,
                 "file smaller than DOS header", Some(ctx.span(0, pe.len() as u64)),
                 None, None);
    }
    let e_magic = pe.get(0..2).map(|b| b.to_vec()).unwrap_or_default();
    dos_fields.push(RawField {
        name: "e_magic".into(),
        value: serde_json::Value::String(String::from_utf8_lossy(&e_magic).into_owned()),
        repr: hexof(&e_magic), span: Some(ctx.span(0, 2)),
    });
    let e_lfanew = rd32(pe, 0x3c) as u64;
    dos_fields.push(RawField {
        name: "e_lfanew".into(),
        value: serde_json::json!(e_lfanew),
        repr: hexof(&pe[0x3c..0x40]), span: Some(ctx.span(0x3c, 4)),
    });
    if &e_magic != b"MZ" {
        ctx.diag("dos_magic_invalid", DiagSeverity::Error,
                 "DOS signature is not MZ", Some(ctx.span(0, 2)), None, None);
    }
    let dos_id = stable_id("raw-dos", &[material_id]);
    facts.raw_records.push(RawRecord {
        id: dos_id, kind: RawKind::DosHeader, ordinal: ctx.next_ord(),
        title: "DOS Header".into(), fields: dos_fields.clone(),
        spans: vec![ctx.span(0, 0x40)],
    });
    facts.dos = Some(DosHeader { e_lfanew, fields: dos_fields });

    // ---- NT headers ----
    let nt_off = e_lfanew as usize;
    if pe.len() < nt_off + 24 {
        ctx.diag("nt_header_truncated", DiagSeverity::Error,
                 "file truncated before NT headers",
                 Some(ctx.span(nt_off as u64, pe.len() as u64 - nt_off as u64)),
                 None, None);
        facts.diagnostics = ctx.diags;
        return facts;
    }
    let pe_sig = &pe[nt_off..nt_off + 4];
    if pe_sig != b"PE\0\0" {
        ctx.diag("nt_signature_invalid", DiagSeverity::Error,
                 "PE signature not found at e_lfanew",
                 Some(ctx.span(nt_off as u64, 4)), None, None);
    }
    let coff = nt_off + 4;
    let machine = rd16(pe, coff);
    let num_sections = rd16(pe, coff + 2);
    let opt_size = rd16(pe, coff + 16) as usize;
    let characteristics = rd16(pe, coff + 18);

    let opt = coff + 20;
    let magic = rd16(pe, opt);
    let pe32_plus = magic == 0x20b;
    let is64 = pe32_plus;
    // Standard + Windows fields layout differs for PE32(0x10b) / PE32+.
    let image_base = if is64 { rd64(pe, opt + 24) } else { rd32(pe, opt + 28) as u64 };
    let section_alignment = rd32(pe, opt + 32) as u64;
    let file_alignment = rd32(pe, opt + 36) as u64;
    let size_of_image = rd32(pe, opt + 56) as u64;
    let size_of_headers = rd32(pe, opt + 60) as u64;
    let num_dirs_off = if is64 { opt + 108 } else { opt + 92 };
    let num_dirs = rd32(pe, num_dirs_off) as usize;
    let dirs_off = num_dirs_off + 4;

    let mut nt_fields = vec![
        field(&mut ctx, "Signature", pe_sig, nt_off as u64,
              serde_json::Value::String(format!("{:?}", pe_sig))),
        field(&mut ctx, "Machine", &pe[coff..coff + 2], nt_off as u64 + 4,
              serde_json::json!(machine)),
        field(&mut ctx, "NumberOfSections", &pe[coff + 2..coff + 4],
              nt_off as u64 + 6, serde_json::json!(num_sections)),
        field(&mut ctx, "Characteristics", &pe[coff + 18..coff + 20],
              nt_off as u64 + 4 + 18, serde_json::json!(characteristics)),
        field(&mut ctx, "OptionalHeader.Magic", &pe[opt..opt + 2],
              opt as u64, serde_json::json!(magic)),
        field(&mut ctx, "ImageBase",
              &pe[if is64 { opt + 24 } else { opt + 28 }
                  ..if is64 { opt + 32 } else { opt + 32 }],
              if is64 { opt as u64 + 24 } else { opt as u64 + 28 },
              serde_json::json!(image_base)),
        field(&mut ctx, "SectionAlignment", &pe[opt + 32..opt + 36],
              opt as u64 + 32, serde_json::json!(section_alignment)),
        field(&mut ctx, "FileAlignment", &pe[opt + 36..opt + 40],
              opt as u64 + 36, serde_json::json!(file_alignment)),
        field(&mut ctx, "SizeOfImage", &pe[opt + 56..opt + 60],
              opt as u64 + 56, serde_json::json!(size_of_image)),
        field(&mut ctx, "SizeOfHeaders", &pe[opt + 60..opt + 64],
              opt as u64 + 60, serde_json::json!(size_of_headers)),
    ];
    let nt_id = stable_id("raw-nt", &[material_id]);
    facts.raw_records.push(RawRecord {
        id: nt_id, kind: RawKind::NtHeaders, ordinal: ctx.next_ord(),
        title: "NT Headers (COFF + Optional)".into(),
        fields: nt_fields.clone(),
        spans: vec![ctx.span(nt_off as u64, (24 + opt_size) as u64)],
    });
    facts.nt = Some(NtHeaders {
        machine, pe32_plus, image_base, size_of_image, size_of_headers,
        section_alignment, file_alignment, num_sections, fields: nt_fields,
    });

    // ---- Section table ----
    let sec_tab = dirs_off + num_dirs * 8;
    let mut sections = Vec::new();
    for i in 0..num_sections as usize {
        let so = sec_tab + i * 40;
        if so + 40 > pe.len() {
            ctx.diag("section_row_truncated", DiagSeverity::Error,
                     format!("section row {} extends past file", i),
                     Some(ctx.span(so as u64, 40)), None, None);
            break;
        }
        let nameb = &pe[so..so + 8];
        let name_end = nameb.iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&nameb[..name_end]).into_owned();
        let virtual_size = rd32(pe, so + 8) as u64;
        let virtual_address = rd32(pe, so + 12) as u64;
        let raw_size = rd32(pe, so + 16) as u64;
        let raw_offset = rd32(pe, so + 20) as u64;
        let characteristics = rd32(pe, so + 36);
        let fields = vec![
            field(&mut ctx, "Name", nameb, so as u64,
                  serde_json::Value::String(name.clone())),
            field(&mut ctx, "VirtualSize", &pe[so + 8..so + 12], so as u64 + 8,
                  serde_json::json!(virtual_size)),
            field(&mut ctx, "VirtualAddress", &pe[so + 12..so + 16], so as u64 + 12,
                  serde_json::json!(virtual_address)),
            field(&mut ctx, "SizeOfRawData", &pe[so + 16..so + 20], so as u64 + 16,
                  serde_json::json!(raw_size)),
            field(&mut ctx, "PointerToRawData", &pe[so + 20..so + 24], so as u64 + 20,
                  serde_json::json!(raw_offset)),
            field(&mut ctx, "Characteristics", &pe[so + 36..so + 40], so as u64 + 36,
                  serde_json::json!(characteristics)),
        ];
        let hdr_span = ctx.span(so as u64, 40);
        let id = stable_id("raw-sec", &[material_id, &i.to_string()]);
        facts.raw_records.push(RawRecord {
            id, kind: RawKind::Section, ordinal: ctx.next_ord(),
            title: format!("Section #{} {}", i, name),
            fields: fields.clone(), spans: vec![hdr_span.clone()],
        });
        if virtual_size > raw_size {
            ctx.diag("virtual_size_gt_raw", DiagSeverity::Warning,
                     format!("section {} virtual size 0x{:x} > raw size 0x{:x}; tail is zero-fill",
                             name, virtual_size, raw_size),
                     Some(hdr_span.clone()), Some(Q::rva(virtual_address)), Some(id));
        }
        sections.push(Section {
            index: i as u32, name, virtual_address, virtual_size,
            raw_offset, raw_size, characteristics, fields, hdr_span,
        });
    }
    // Detect overlapping virtual ranges.
    for i in 0..sections.len() {
        for j in (i + 1)..sections.len() {
            let (a, b) = (&sections[i], &sections[j]);
            let ae = a.virtual_address + a.virtual_size.max(a.raw_size);
            let be = b.virtual_address + b.virtual_size.max(b.raw_size);
            if a.virtual_address < be && b.virtual_address < ae {
                ctx.diag("sections_overlap", DiagSeverity::Warning,
                         format!("sections {} and {} virtual ranges overlap",
                                 a.name, b.name),
                         Some(ctx.span(b.raw_offset, 0)),
                         Some(Q::rva(b.virtual_address)), None);
            }
        }
    }
    facts.sections = sections.clone();

    // ---- Data directories ----
    let mut directories = Vec::new();
    for i in 0..num_dirs {
        let doff = dirs_off + i * 8;
        if doff + 8 > pe.len() {
            break;
        }
        let rva = rd32(pe, doff) as u64;
        let size = rd32(pe, doff + 4) as u64;
        let label = DIR_LABELS.get(i).copied().unwrap_or("UNKNOWN").to_string();
        let f = RawField {
            name: format!("DataDirectory[{}:{}]", i, label),
            value: serde_json::json!({"rva": rva, "size": size}),
            repr: hexof(&pe[doff..doff + 8]),
            span: Some(ctx.span(doff as u64, 8)),
        };
        if rva != 0 || size != 0 {
            let id = stable_id("raw-dir", &[material_id, &i.to_string()]);
            facts.raw_records.push(RawRecord {
                id: id.clone(), kind: RawKind::DataDirectory, ordinal: ctx.next_ord(),
                title: format!("Data Directory {} ({})", i, label),
                fields: vec![f.clone()], spans: vec![ctx.span(doff as u64, 8)],
            });
        }
        directories.push(DataDirectory {
            index: i as u32, label, rva, size, field: f,
        });
    }
    facts.directories = directories.clone();

    // ---- Relocation directory ----
    if let Some(rd) = directories.get(5) {
        if rd.rva != 0 && rd.size != 0 {
            parse_relocs(&mut ctx, &mut facts, &sections, rd.rva, rd.size);
        }
    }

    // ---- Import directory ----
    if let Some(idir) = directories.get(1) {
        if idir.rva != 0 && idir.size != 0 {
            parse_imports(&mut ctx, &mut facts, &sections, idir.rva, idir.size, is64);
        }
    }

    facts.diagnostics = ctx.diags;
    facts
}

fn field(ctx: &mut Ctx, name: &str, bytes: &[u8], file_offset: u64,
         value: serde_json::Value) -> RawField {
    RawField {
        name: name.into(),
        repr: hexof(bytes),
        span: Some(ctx.span(file_offset, bytes.len() as u64)),
        value,
    }
}

fn parse_relocs(
    ctx: &mut Ctx,
    facts: &mut PeFacts,
    sections: &[Section],
    dir_rva: u64,
    dir_size: u64,
) {
    let soi = facts.nt.as_ref().map(|n| n.size_of_image).unwrap_or(u64::MAX);
    let blk_id_for = |idx: u32| stable_id("raw-rb", &[&facts.pe_material_id, &idx.to_string()]);

    if dir_size > 0 && dir_rva.checked_add(dir_size).map_or(true, |e| e > soi) {
        ctx.diag("reloc_directory_exceeds_image", DiagSeverity::Error,
                 format!("relocation directory [rva 0x{:x} +0x{:x}] extends past SizeOfImage 0x{:x}",
                         dir_rva, dir_size, soi),
                 None, Some(Q::rva(dir_rva)), None);
    }

    let mut cur = dir_rva;
    let end = dir_rva.saturating_add(dir_size);
    let mut bidx = 0u32;
    let mut eidx_global = 0u32;
    while cur + 8 <= end && cur + 8 <= soi {
        let hres = mapper::resolve_range(sections, cur, 8);
        let origin = match hres.kind {
            mapper::ResolutionKind::Unmapped => {
                ctx.diag("reloc_unmapped", DiagSeverity::Error,
                         format!("relocation block header at rva 0x{:x} has no mapped section", cur),
                         None, Some(Q::rva(cur)), Some(blk_id_for(bidx)));
                break;
            }
            mapper::ResolutionKind::Overlapping => {
                ctx.diag("reloc_overlapping_sections", DiagSeverity::Error,
                         format!("relocation block header at rva 0x{:x} maps to overlapping sections", cur),
                         None, Some(Q::rva(cur)), Some(blk_id_for(bidx)));
                break;
            }
            mapper::ResolutionKind::ZeroFillOnly => {
                ctx.diag("reloc_terminator_in_zerofill", DiagSeverity::Warning,
                         format!("zero relocation block encountered in zero-fill tail at rva 0x{:x}", cur),
                         None, Some(Q::rva(cur)), Some(blk_id_for(bidx)));
                break;
            }
            mapper::ResolutionKind::Unique => hres.origins[0].clone(),
        };
        let hdr = mapper::read_bytes(ctx.pe, sections, &origin, 8);
        let page_rva = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as u64;
        let block_size = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as u64;
        let bid = blk_id_for(bidx);
        if page_rva == 0 && block_size == 0 {
            break; // normal terminating block
        }
        if block_size < 8 || block_size % 2 != 0 {
            ctx.diag("reloc_block_size_invalid", DiagSeverity::Error,
                     format!("relocation block at rva 0x{:x} has invalid size 0x{:x}", cur, block_size),
                     origin.file_offset.map(|o| ctx.span(o, 8)), Some(Q::rva(cur)), Some(bid));
            break;
        }
        if page_rva >= soi {
            ctx.diag("reloc_block_page_outside_image", DiagSeverity::Error,
                     format!("relocation block page rva 0x{:x} >= SizeOfImage 0x{:x}", page_rva, soi),
                     None, Some(Q::rva(page_rva)), Some(bid));
        }

        // Determine how much of the block body is actually raw-backed.
        let body_len = block_size - 8;
        let bres = mapper::resolve_range(sections, cur, block_size);
        let mut overflowed = false;
        match bres.kind {
            mapper::ResolutionKind::Unmapped => overflowed = true,
            mapper::ResolutionKind::ZeroFillOnly => overflowed = true,
            _ => {
                for o in &bres.origins {
                    if matches!(o.kind, OriginKind::ZeroFill | OriginKind::PartialRaw) {
                        overflowed = true;
                    }
                }
            }
        }
        if overflowed {
            ctx.diag("reloc_block_overflow", DiagSeverity::Error,
                     format!("relocation block at rva 0x{:x} (size 0x{:x}) runs past raw data into zero-fill/unmapped bytes",
                             cur, block_size),
                     origin.file_offset.map(|o| ctx.span(o, 8)),
                     Some(Q::rva(cur)), Some(bid.clone()));
        }

        let mut entries = Vec::new();
        let n_words = body_len / 2;
        let body_file = origin.file_offset.map(|o| o + 8);
        for k in 0..n_words as usize {
            let entry_rva = cur + 8 + (k as u64) * 2;
            // Only read words still inside raw region.
            let wres = mapper::resolve_range(sections, entry_rva, 2);
            let word = if wres.kind == mapper::ResolutionKind::Unique
                && wres.origins[0].kind == OriginKind::Raw
            {
                let fo = wres.origins[0].file_offset.unwrap();
                rd16(ctx.pe, fo as usize)
            } else {
                0
            };
            let raw_type = (word >> 12) as u8;
            let off = (word & 0x0fff) as u16;
            let target = page_rva + off as u64;
            let span = body_file.map(|bf| ctx.span(bf + k as u64 * 2, 2));
            let f = RawField {
                name: format!("entry[{}]", k),
                value: serde_json::json!({
                    "type": raw_type, "offset": off, "target_rva": target
                }),
                repr: format!("{:04x}", word),
                span: span.clone(),
            };
            let eid = stable_id("raw-re", &[&facts.pe_material_id, &eidx_global.to_string()]);
            facts.raw_records.push(RawRecord {
                id: eid, kind: RawKind::RelocationEntry, ordinal: ctx.next_ord(),
                title: format!("Reloc entry type{} off 0x{:x} -> rva 0x{:x}",
                               raw_type, off, target),
                fields: vec![f.clone()], spans: span.map(|s| vec![s]).unwrap_or_default(),
            });
            entries.push(RelocEntryRaw {
                block_index: bidx, index: eidx_global, raw_type, offset: off,
                rva: target, field: f,
            });
            eidx_global += 1;
        }
        let fields = vec![
            RawField { name: "PageRVA".into(), value: serde_json::json!(page_rva),
                       repr: hexof(&hdr[0..4]), span: origin.file_offset.map(|o| ctx.span(o, 4)) },
            RawField { name: "BlockSize".into(), value: serde_json::json!(block_size),
                       repr: hexof(&hdr[4..8]), span: origin.file_offset.map(|o| ctx.span(o + 4, 4)) },
        ];
        let span = origin.file_offset.map(|o| ctx.span(o, block_size));
        let rb = RelocBlockRaw {
            index: bidx, page_rva, block_size, entries,
            fields, span: span.unwrap_or_else(|| ctx.span(cur, block_size)),
        };
        facts.raw_records.push(RawRecord {
            id: bid.clone(), kind: RawKind::RelocationBlock,
            ordinal: ctx.next_ord(),
            title: format!("Relocation block page rva 0x{:x}", page_rva),
            fields: rb.fields.clone(),
            spans: vec![rb.span.clone()],
        });
        facts.reloc_blocks.push(rb);
        bidx += 1;
        cur += block_size;
    }
}
