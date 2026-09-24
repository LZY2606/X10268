//! PE32/PE32+ 字节解析：只提取原始材料，不做装载语义推断。
//! 解析结果保留字段的原始十六进制表示、字节来源与诊断。

use crate::model::{ByteSource, Diagnostic, Material, Coord};
use serde_json::json;

pub const IMAGE_REL_BASED_ABSOLUTE: i64 = 0;
pub const IMAGE_REL_BASED_HIGHLOW: i64 = 3;
pub const IMAGE_REL_BASED_DIR64: i64 = 10;

pub const IMPORT_BY_NAME_FLAG64: i64 = 0x7FFF_FFFF_FFFF_FFFFu64 as i64;

#[derive(Debug, Clone)]
pub struct ParseOutput {
    pub expected_image_base: i64,
    pub materials: Vec<Material>,
}

struct Cursor<'a> {
    data: &'a [u8],
    artifact_id: &'a str,
    diagnostics: Vec<Diagnostic>,
}

impl<'a> Cursor<'a> {
    fn u8(&mut self, off: usize, field: &str) -> Option<u8> {
        self.data.get(off).copied().or_else(|| {
            self.diagnostics.push(Diagnostic {
                code: "pe.read_oob".into(),
                severity: "error".into(),
                message: format!("读取 byte 越界 offset=0x{off:X} field={field}"),
                byte_source: Some(self.src(off, 1, field)),
            });
            None
        })
    }
    fn u16(&mut self, off: usize, field: &str) -> Option<u16> {
        if off + 2 > self.data.len() {
            self.u8(off, field)?;
            return None;
        }
        Some(u16::from_le_bytes([self.data[off], self.data[off + 1]]))
    }
    fn u32(&mut self, off: usize, field: &str) -> Option<u32> {
        if off + 4 > self.data.len() {
            self.u8(off, field)?;
            return None;
        }
        Some(u32::from_le_bytes(self.data[off..off + 4].try_into().unwrap()))
    }
    fn u64(&mut self, off: usize, field: &str) -> Option<u64> {
        if off + 8 > self.data.len() {
            self.diagnostics.push(Diagnostic {
                code: "pe.read_oob".into(),
                severity: "error".into(),
                message: format!("读取 u64 越界 offset=0x{off:X} field={field}"),
                byte_source: Some(self.src(off, 8, field)),
            });
            return None;
        }
        Some(u64::from_le_bytes(self.data[off..off + 8].try_into().unwrap()))
    }
    fn src(&self, off: usize, len: usize, field: &str) -> ByteSource {
        ByteSource {
            artifact_id: self.artifact_id.to_string(),
            offset: off as i64,
            len: len as i64,
            field: field.to_string(),
        }
    }
    fn diag(&mut self, code: &str, severity: &str, msg: String, off: usize, len: usize, field: &str) {
        self.diagnostics.push(Diagnostic {
            code: code.into(),
            severity: severity.into(),
            message: msg,
            byte_source: Some(self.src(off, len, field)),
        });
    }
}

/// 解析 PE 字节。`expected_image_base` 由导入方提供（装载预期），不直接信任 optional header。
pub fn parse_pe(artifact_id: &str, data: &[u8], expected_image_base: i64) -> ParseOutput {
    let mut cur = Cursor { data, artifact_id, diagnostics: Vec::new() };
    let mut materials: Vec<Material> = Vec::new();
    let mut ord = 0i64;
    let mut push = |materials: &mut Vec<Material>, kind: &str, ord: &mut i64,
                    payload: serde_json::Value, sources: Vec<ByteSource>, diags: Vec<Diagnostic>| {
        *ord += 1;
        materials.push(Material {
            id: format!("{artifact_id}:mat:{kind}:{n:03}", n = *ord),
            kind: kind.into(),
            ordinal: *ord,
            payload,
            byte_sources: sources,
            diagnostics: diags,
        });
    };

    // ---- DOS header（只保留语义所需字段，原始表示在 raw_repr）----
    let mut dos_sources = Vec::new();
    let e_magic = cur.u16(0, "dos_header.e_magic");
    let e_lfanew = cur.u32(0x3C, "dos_header.e_lfanew");
    if let Some(m) = e_magic {
        dos_sources.push(cur.src(0, 2, "dos_header.e_magic"));
        if m != 0x5A4D {
            cur.diag("pe.dos_magic", "error", format!("MZ 魔数错误: 0x{m:04X}"), 0, 2, "dos_header.e_magic");
        }
    }
    if let Some(pe) = e_lfanew {
        dos_sources.push(cur.src(0x3C, 4, "dos_header.e_lfanew"));
        let dos_payload = json!({
            "e_magic": {"value": e_magic.map(|v| v as i64), "unit": "u16", "raw_repr": e_magic.map(|v| format!("0x{v:04X}"))},
            "e_lfanew": {"value": pe as i64, "unit": "byte", "raw_repr": format!("0x{pe:08X}")},
        });
        push(&mut materials, "dos_header", &mut ord, dos_payload, dos_sources, drain_diag(&mut cur));
    } else {
        push(&mut materials, "dos_header", &mut ord, json!({"error": "e_lfanew 不可读"}), dos_sources, drain_diag(&mut cur));
        return ParseOutput { expected_image_base, materials };
    }

    let pe = e_lfanew.unwrap() as usize;
    // ---- NT signature + COFF header ----
    let sig = cur.u32(pe, "nt.signature");
    let mut nt_sources = vec![cur.src(pe, 4, "nt.signature")];
    let coff = pe + 4;
    let machine = cur.u16(coff, "coff.machine");
    let num_sections = cur.u16(coff + 2, "coff.number_of_sections");
    let size_optional = cur.u16(coff + 16, "coff.size_of_optional_header");
    nt_sources.push(cur.src(coff, 20, "coff.header"));
    if let Some(s) = sig {
        if s != 0x0000_4550 {
            cur.diag("pe.pe_sig", "error", format!("PE\\0\\0 签名错误: 0x{s:08X}"), pe, 4, "nt.signature");
        }
    }

    // ---- Optional header ----
    let opt = coff + 20;
    let magic = cur.u16(opt, "optional.magic");
    let is64 = magic == Some(0x20B);
    if !matches!(magic, Some(0x10B) | Some(0x20B)) {
        cur.diag("pe.optional_magic", "error",
            format!("optional header magic 无法识别: {:?}", magic.map(|v| format!("0x{v:04X}"))),
            opt, 2, "optional.magic");
    }
    let image_base_i64 = if is64 {
        cur.u64(opt + 24, "optional.image_base").map(|v| v as i64)
    } else {
        cur.u32(opt + 28, "optional.image_base").map(|v| v as i64)
    };
    let sect_align = cur.u32(opt + 32, "optional.section_alignment");
    let file_align = cur.u32(opt + 36, "optional.file_alignment");
    let size_image = cur.u32(opt + 56, "optional.size_of_image");
    let size_headers = cur.u32(opt + 60, "optional.size_of_headers");
    let num_dirs = cur.u32(opt + if is64 { 108 } else { 92 }, "optional.number_of_rva_and_sizes")
        .unwrap_or(0) as usize;
    let dir_off = opt + if is64 { 112 } else { 96 };
    nt_sources.push(cur.src(opt, size_optional.map(|v| v as usize).unwrap_or(0), "optional.header"));

    let nt_payload = json!({
        "signature": {"value": sig.map(|v| v as i64), "unit": "u32", "raw_repr": sig.map(|v| format!("0x{v:08X}"))},
        "machine": {"value": machine.map(|v| v as i64), "unit": "u16", "raw_repr": machine.map(|v| format!("0x{v:04X}"))},
        "number_of_sections": num_sections.map(|v| v as i64),
        "size_of_optional_header": {"value": size_optional.map(|v| v as i64), "unit": "byte"},
        "optional_magic": {"value": magic.map(|v| v as i64), "unit": "u16", "raw_repr": magic.map(|v| format!("0x{v:04X}"))},
        "pe_class": if is64 { "PE32+" } else { "PE32" },
        "image_base_header": {"value": image_base_i64, "unit": "va", "raw_repr": image_base_i64.map(|v| format!("0x{v:016X}"))},
        "expected_image_base": {"value": expected_image_base, "unit": "va", "raw_repr": format!("0x{expected_image_base:016X}")},
        "section_alignment": {"value": sect_align.map(|v| v as i64), "unit": "byte"},
        "file_alignment": {"value": file_align.map(|v| v as i64), "unit": "byte"},
        "size_of_image": {"value": size_image.map(|v| v as i64), "unit": "rva"},
        "size_of_headers": {"value": size_headers.map(|v| v as i64), "unit": "byte"},
        "number_of_rva_and_sizes": num_dirs as i64,
    });
    push(&mut materials, "nt_header", &mut ord, nt_payload, nt_sources, drain_diag(&mut cur));

    let directories = parse_directories(&mut cur, artifact_id, dir_off, num_dirs, &mut materials, &mut ord);

    // ---- Section table ----
    let sect_table = opt + size_optional.unwrap_or(0) as usize;
    let sections = parse_sections(&mut cur, artifact_id, sect_table,
        num_sections.unwrap_or(0) as usize, data.len(), &mut materials, &mut ord);

    // ---- Base relocation blocks ----
    parse_relocations(&mut cur, artifact_id, &directories, &sections, &mut materials, &mut ord);
    // ---- Import descriptors / thunks / ordinal/name ----
    parse_imports(&mut cur, artifact_id, &directories, &sections, data, &mut materials, &mut ord);

    ParseOutput { expected_image_base, materials }
}

fn drain_diag(cur: &mut Cursor) -> Vec<Diagnostic> {
    std::mem::take(&mut cur.diagnostics)
}

#[derive(Debug, Clone)]
pub struct Directory {
    pub index: usize,
    pub name: String,
    pub rva: i64,
    pub size: i64,
}

pub const DIR_NAMES: &[&str] = &[
    "export", "import", "resource", "exception", "certificate", "base_reloc",
    "debug", "architecture", "global_ptr", "tls", "load_config", "bound_import",
    "iat", "delay_import", "clr", "reserved",
];

fn parse_directories(cur: &mut Cursor, art: &str, dir_off: usize, num: usize,
                     materials: &mut Vec<Material>, ord: &mut i64) -> Vec<Directory> {
    let mut dirs = Vec::new();
    let mut entries = Vec::new();
    let mut sources = Vec::new();
    for i in 0..num.max(16) {
        let off = dir_off + i * 8;
        let rva = cur.u32(off, &format!("data_directory[{i}].rva")).unwrap_or(0) as i64;
        let size = cur.u32(off + 4, &format!("data_directory[{i}].size")).unwrap_or(0) as i64;
        if i < num {
            sources.push(cur.src(off, 8, &format!("data_directory[{i}]")));
            let name = DIR_NAMES.get(i).copied().unwrap_or("unknown");
            entries.push(json!({
                "index": i, "name": name,
                "virtual_address": {"value": rva, "unit": "rva", "raw_repr": format!("0x{rva:08X}")},
                "size": {"value": size, "unit": "byte", "raw_repr": format!("0x{size:08X}")},
            }));
            dirs.push(Directory { index: i, name: name.into(), rva, size });
        }
    }
    *ord += 1;
    materials.push(Material {
        id: format!("{art}:mat:data_directory:{n:03}", n = *ord),
        kind: "data_directory".into(), ordinal: *ord,
        payload: json!({ "entries": entries }),
        byte_sources: sources,
        diagnostics: drain_diag(cur),
    });
    dirs
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub virtual_size_raw: i64,
    pub virtual_address: i64,
    pub size_of_raw_data: i64,
    pub pointer_to_raw_data: i64,
    pub characteristics: i64,
}

/// 判定 [rva, rva+len) 是否落在某个 section 的虚拟区间内（不做唯一选择）。
pub fn sections_containing(sections: &[Section], rva: i64, len: i64) -> Vec<usize> {
    sections.iter().enumerate().filter(|(_, s)| {
        let vs = s.virtual_size_raw.max(0);
        rva >= s.virtual_address && rva < s.virtual_address + vs && len >= 0
            && rva + len <= s.virtual_address + vs
    }).map(|(i, _)| i).collect()
}

fn parse_sections(cur: &mut Cursor, art: &str, table: usize, num: usize, file_len: usize,
                  materials: &mut Vec<Material>, ord: &mut i64) -> Vec<Section> {
    let mut sections = Vec::new();
    for i in 0..num {
        let off = table + i * 40;
        let name_bytes = cur.data.get(off..off + 8).map(|b| {
            let n = b.iter().position(|&c| c == 0).unwrap_or(8);
            String::from_utf8_lossy(&b[..n]).to_string()
        }).unwrap_or_default();
        let vsize = cur.u32(off + 8, &format!("section[{i}].virtual_size")).unwrap_or(0) as i64;
        let vaddr = cur.u32(off + 12, &format!("section[{i}].virtual_address")).unwrap_or(0) as i64;
        let rsize = cur.u32(off + 16, &format!("section[{i}].size_of_raw_data")).unwrap_or(0) as i64;
        let rptr = cur.u32(off + 20, &format!("section[{i}].pointer_to_raw_data")).unwrap_or(0) as i64;
        let chars = cur.u32(off + 36, &format!("section[{i}].characteristics")).unwrap_or(0) as i64;
        let sources = vec![cur.src(off, 40, &format!("section[{i}]"))];
        // raw 范围与文件实际长度的关系作为诊断保留（raw 指针超出 EOF：可读区间为空/零填充）。
        let mut diags = drain_diag(cur);
        if rptr + rsize > file_len as i64 {
            diags.push(Diagnostic {
                code: "pe.section_raw_beyond_eof".into(), severity: "warning".into(),
                message: format!("section[{i}] {name_bytes} raw 区间 [0x{rptr:X},0x{:X}) 超出文件 EOF=0x{file_len:X}",
                    rptr + rsize),
                byte_source: Some(cur.src(off + 20, 8, &format!("section[{i}].raw_range"))),
            });
        }
        *ord += 1;
        materials.push(Material {
            id: format!("{art}:mat:section_header:{n:03}", n = *ord),
            kind: "section_header".into(), ordinal: *ord,
            payload: json!({
                "index": i, "name": name_bytes,
                "virtual_size": {"value": vsize, "unit": "byte", "raw_repr": format!("0x{vsize:08X}")},
                "virtual_address": {"value": vaddr, "unit": "rva", "raw_repr": format!("0x{vaddr:08X}")},
                "size_of_raw_data": {"value": rsize, "unit": "byte", "raw_repr": format!("0x{rsize:08X}")},
                "pointer_to_raw_data": {"value": rptr, "unit": "byte", "raw_repr": format!("0x{rptr:08X}")},
                "characteristics": {"value": chars, "unit": "bitfield", "raw_repr": format!("0x{chars:08X}")},
            }),
            byte_sources: sources, diagnostics: diags,
        });
        sections.push(Section {
            name: name_bytes, virtual_size_raw: vsize, virtual_address: vaddr,
            size_of_raw_data: rsize, pointer_to_raw_data: rptr, characteristics: chars,
        });
    }
    sections
}

/// RVA -> 文件读取候选（解析层只做范围查找，不决定唯一映射；损坏范围在此诊断）。
pub fn read_at_rva(data: &[u8], sections: &[Section], rva: i64, len: usize) -> Vec<(usize, Vec<u8>)> {
    let mut out = Vec::new();
    for (idx, s) in sections.iter().enumerate() {
        let off_in_sect = rva - s.virtual_address;
        if off_in_sect < 0 || off_in_sect >= s.virtual_size_raw {
            continue;
        }
        let raw_end = s.size_of_raw_data.min(s.virtual_size_raw);
        if off_in_sect >= raw_end {
            // 落在 raw 之外、virtual 之内：只有零填充，不产出字节，但可作为 zero_fill 候选由调用方判断。
            out.push((idx, Vec::new()));
            continue;
        }
        let avail = (raw_end - off_in_sect) as usize;
        let take = len.min(avail);
        let start = (s.pointer_to_raw_data + off_in_sect) as usize;
        if start < data.len() {
            let mut bytes = data[start..start.min(data.len())].get(..take).unwrap_or(&[]).to_vec();
            if bytes.len() < len {
                // 超出 raw 的部分零填充：候选字节保留，但由装载层显式标记。
                bytes.resize(len, 0);
            }
            out.push((idx, bytes));
        }
    }
    out
}

fn parse_relocations(cur: &mut Cursor, art: &str, dirs: &[Directory], sections: &[Section],
                     materials: &mut Vec<Material>, ord: &mut i64) {
    let Some(dir) = dirs.iter().find(|d| d.name == "base_reloc") else { return; };
    if dir.rva == 0 {
        *ord += 1;
        materials.push(Material {
            id: format!("{art}:mat:relocation_table:{n:03}", n = *ord),
            kind: "relocation_table".into(), ordinal: *ord,
            payload: json!({"present": false}), byte_sources: vec![], diagnostics: vec![],
        });
        return;
    }
    // 损坏 directory 范围：directory 区间无法被任何 section 完整覆盖。
    let cover = sections_containing(sections, dir.rva, dir.size);
    let mut diags = Vec::new();
    if cover.is_empty() {
        diags.push(Diagnostic {
            code: "pe.corrupt_directory_range".into(), severity: "error".into(),
            message: format!("base_reloc data directory RVA=0x{:X} size=0x{:X} 无 section 覆盖（损坏范围）",
                dir.rva, dir.size),
            byte_source: None,
        });
    }
    let mut blocks = Vec::new();
    let mut sources = Vec::new();
    let candidates = read_at_rva(cur.data, sections, dir.rva, dir.size.max(0) as usize);
    if let Some((_, bytes)) = candidates.into_iter().next() {
        let mut p = 0usize;
        while p + 8 <= bytes.len() {
            let page_rva = u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap()) as i64;
            let block_size = u32::from_le_bytes(bytes[p + 4..p + 8].try_into().unwrap()) as i64;
            if block_size < 8 || block_size > (bytes.len() - p) as i64 {
                diags.push(Diagnostic {
                    code: "pe.reloc_block_overflow".into(), severity: "error".into(),
                    message: format!("重定位块 page=0x{page_rva:X} block_size=0x{block_size:X} 溢出 directory 范围"),
                    byte_source: None,
                });
                break;
            }
            let count = ((block_size - 8) / 2) as usize;
            let mut entries = Vec::new();
            for k in 0..count {
                let word = u16::from_le_bytes(bytes[p + 8 + k * 2..p + 10 + k * 2].try_into().unwrap());
                let kind = (word >> 12) as i64;
                let offset = (word & 0x0FFF) as i64;
                entries.push(json!({
                    "type": kind,
                    "type_name": reloc_type_name(kind),
                    "offset": {"value": offset, "unit": "byte", "raw_repr": format!("0x{offset:03X}")},
                    "target_rva": {"value": page_rva + offset, "unit": "rva", "raw_repr": format!("0x{:08X}", page_rva + offset)},
                    "entry_raw": format!("0x{word:04X}"),
                }));
            }
            sources.push(ByteSource { artifact_id: art.into(), offset: dir.rva, len: block_size,
                field: format!("relocation_block@0x{page_rva:X}") });
            blocks.push(json!({
                "page_rva": {"value": page_rva, "unit": "rva", "raw_repr": format!("0x{page_rva:08X}")},
                "block_size": {"value": block_size, "unit": "byte"},
                "entries": entries,
            }));
            p += block_size as usize;
        }
    }
    *ord += 1;
    materials.push(Material {
        id: format!("{art}:mat:relocation_table:{n:03}", n = *ord),
        kind: "relocation_table".into(), ordinal: *ord,
        payload: json!({"present": true, "directory_rva": dir.rva, "directory_size": dir.size,
                        "covering_sections": cover, "blocks": blocks}),
        byte_sources: sources, diagnostics: diags,
    });
}

pub fn reloc_type_name(kind: i64) -> &'static str {
    match kind {
        0 => "ABSOLUTE", 1 => "HIGH", 2 => "LOW", 3 => "HIGHLOW", 4 => "HIGHADJ",
        10 => "DIR64", _ => "UNKNOWN",
    }
}

fn cstr_at_rva(data: &[u8], sections: &[Section], rva: i64, max: usize) -> Option<String> {
    let cands = read_at_rva(data, sections, rva, max);
    let (_, bytes) = cands.into_iter().next()?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    Some(String::from_utf8_lossy(&bytes[..end]).to_string())
}

fn parse_imports(cur: &mut Cursor, art: &str, dirs: &[Directory], sections: &[Section], data: &[u8],
                 materials: &mut Vec<Material>, ord: &mut i64) {
    let Some(dir) = dirs.iter().find(|d| d.name == "import") else { return; };
    let mut diags = Vec::new();
    let cover = sections_containing(sections, dir.rva, dir.size);
    if dir.rva != 0 && cover.is_empty() {
        diags.push(Diagnostic {
            code: "pe.corrupt_directory_range".into(), severity: "error".into(),
            message: format!("import data directory RVA=0x{:X} size=0x{:X} 无 section 覆盖（损坏范围）",
                dir.rva, dir.size),
            byte_source: None,
        });
    }
    let mut descriptors = Vec::new();
    let mut thunks = Vec::new();
    let mut sources = Vec::new();
    let desc_candidates = if dir.rva == 0 {
        Vec::new()
    } else {
        read_at_rva(data, sections, dir.rva, dir.size.max(20) as usize)
    };
    if let Some((_, dbytes)) = desc_candidates.into_iter().next() {
        let mut p = 0usize;
        let mut d_idx = 0i64;
        while p + 20 <= dbytes.len() {
            let ilt_rva = u32::from_le_bytes(dbytes[p..p + 4].try_into().unwrap()) as i64;
            let _time = u32::from_le_bytes(dbytes[p + 4..p + 8].try_into().unwrap());
            let _fwd = u32::from_le_bytes(dbytes[p + 8..p + 12].try_into().unwrap());
            let name_rva = u32::from_le_bytes(dbytes[p + 12..p + 16].try_into().unwrap()) as i64;
            let iat_rva = u32::from_le_bytes(dbytes[p + 16..p + 20].try_into().unwrap()) as i64;
            if ilt_rva == 0 && name_rva == 0 && iat_rva == 0 {
                break;
            }
            let dll_name = cstr_at_rva(data, sections, name_rva, 256).unwrap_or_else(|| "<unreadable>".into());
            sources.push(ByteSource { artifact_id: art.into(), offset: dir.rva + p as i64, len: 20,
                field: format!("import_descriptor[{d_idx}]") });
            descriptors.push(json!({
                "index": d_idx,
                "dll_name": dll_name,
                "original_first_thunk": {"value": ilt_rva, "unit": "rva", "raw_repr": format!("0x{ilt_rva:08X}")},
                "name_rva": {"value": name_rva, "unit": "rva", "raw_repr": format!("0x{name_rva:08X}")},
                "first_thunk": {"value": iat_rva, "unit": "rva", "raw_repr": format!("0x{iat_rva:08X}")},
            }));

            // thunk：优先 ILT，否则 IAT
            let thunk_rva = if ilt_rva != 0 { ilt_rva } else { iat_rva };
            let mut t_idx = 0i64;
            loop {
                let cands = read_at_rva(data, sections, thunk_rva + t_idx * 8, 8);
                let Some((_, tb)) = cands.into_iter().next() else {
                    diags.push(Diagnostic {
                        code: "pe.thunk_unmapped".into(), severity: "warning".into(),
                        message: format!("{dll_name} thunk[{t_idx}] RVA=0x{:X} 无映射", thunk_rva + t_idx * 8),
                        byte_source: None,
                    });
                    break;
                };
                let val = u64::from_le_bytes(tb[..8].try_into().unwrap());
                if val == 0 { break; }
                let is_ordinal = (val >> 63) == 1;
                let thunk = if is_ordinal {
                    let ordinal = (val & 0xFFFF) as i64;
                    json!({
                        "dll_name": dll_name, "index": t_idx,
                        "thunk_rva": {"value": iat_rva + t_idx * 8, "unit": "rva"},
                        "ilt_rva": {"value": if ilt_rva != 0 { ilt_rva + t_idx * 8 } else { 0 }, "unit": "rva"},
                        "raw_value": format!("0x{val:016X}"),
                        "import_by": "ordinal", "ordinal": ordinal,
                    })
                } else {
                    let hint_name_rva = (val & 0x7FFF_FFFF_FFFF_FFFF) as i64;
                    let hint = read_at_rva(data, sections, hint_name_rva, 2).into_iter().next()
                        .map(|(_, b)| u16::from_le_bytes([b[0], b[1]]) as i64);
                    let name = cstr_at_rva(data, sections, hint_name_rva + 2, 256)
                        .unwrap_or_else(|| "<unreadable>".into());
                    json!({
                        "dll_name": dll_name, "index": t_idx,
                        "thunk_rva": {"value": iat_rva + t_idx * 8, "unit": "rva"},
                        "ilt_rva": {"value": if ilt_rva != 0 { ilt_rva + t_idx * 8 } else { 0 }, "unit": "rva"},
                        "raw_value": format!("0x{val:016X}"),
                        "import_by": "name", "hint": hint, "name": name,
                        "hint_name_rva": {"value": hint_name_rva, "unit": "rva"},
                    })
                };
                thunks.push(thunk);
                t_idx += 1;
                if t_idx > 4096 { break; }
            }
            d_idx += 1;
            p += 20;
        }
    }
    *ord += 1;
    materials.push(Material {
        id: format!("{art}:mat:import_table:{n:03}", n = *ord),
        kind: "import_table".into(), ordinal: *ord,
        payload: json!({"directory_rva": dir.rva, "directory_size": dir.size,
                        "covering_sections": cover, "descriptors": descriptors, "thunks": thunks}),
        byte_sources: sources, diagnostics: diags,
    });
}

/// 导出快照（DLL 侧，材料来自独立 artifact）。
pub fn parse_export_snapshot(artifact_id: &str, raw: &serde_json::Value, ordinal: i64) -> Material {
    Material {
        id: format!("{artifact_id}:mat:export_snapshot:{ordinal:03}"),
        kind: "export_snapshot".into(), ordinal,
        payload: raw.clone(), byte_sources: vec![], diagnostics: vec![],
    }
}

#[allow(dead_code)]
fn _coord_marker(_c: Coord) {}
