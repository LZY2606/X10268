//! 装载语义推导：
//! - RVA -> 文件偏移可能是无映射、重叠（多候选）或仅零填充，引擎不强行选一；
//! - 重定位严格按类型与位宽执行，32 位 HIGHLOW 做无符号溢出判定；
//! - 缺失 DLL / 缺失导出只产生 unresolved import，不产生伪绑定。

use crate::pe_parser::PeFacts;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize)]
pub struct SectionInterval {
    pub section_id: String,
    pub name: String,
    pub ordinal: usize,
    pub virtual_start: u32, // rva
    pub virtual_end: u32,   // exclusive
    pub raw_start: Option<u32>,
    pub raw_end: Option<u32>,
    pub raw_virtual_gap: bool, // virtual size > raw size
}

#[derive(Debug, Clone, Serialize)]
pub struct MappingCandidate {
    pub kind: String, // MAPPED_RAW | ZERO_FILL | UNMAPPED
    pub section_id: Option<String>,
    pub section_name: Option<String>,
    pub file_offset: Option<u32>,
    pub basis: &'static str,
    pub note: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelocPatch {
    pub reloc_id: String,
    pub block_index: usize,
    pub entry_index: usize,
    pub type_name: String,
    pub width_bytes: u8,
    pub target_rva: u32,
    pub original_value: Option<String>,
    pub patched_value: Option<String>,
    pub status: String, // PATCHED | OVERFLOW | UNSUPPORTED | NOT_APPLICABLE | UNMAPPED_TARGET
    pub candidates: Vec<MappingCandidate>,
    pub diagnostic_code: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportBinding {
    pub import_id: String,
    pub descriptor_index: usize,
    pub thunk_index: usize,
    pub dll_name: String,
    pub by_ordinal: bool,
    pub ordinal: Option<u16>,
    pub symbol_name: Option<String>,
    pub status: String, // RESOLVED | RESOLVED_FORWARDED | UNRESOLVED_MISSING_DLL
                        // | UNRESOLVED_MISSING_EXPORT | UNRESOLVED_FORWARDER_MISSING_DLL
    pub resolved_va: Option<String>,
    pub forward_chain: Vec<String>,
    pub source_export: Option<String>, // 来源导出快照的稳定引用
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DerivedView {
    pub rule_version: String,
    pub image_base_used: String,
    pub sections: Vec<SectionInterval>,
    pub reloc_patches: Vec<RelocPatch>,
    pub imports: Vec<ImportBinding>,
}

#[derive(Debug, Clone)]
pub struct ExportEntry {
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    pub rva_value: Option<u64>,
    pub forwarder: Option<String>,
    pub record_ref: String,
}

#[derive(Debug, Clone)]
pub struct DllSnapshot {
    pub name: String,
    pub image_base: u64,
    pub exports: Vec<ExportEntry>,
}

pub fn parse_snapshots(json_text: &str, source_id: &str) -> Result<(Vec<DllSnapshot>, Vec<String>), String> {
    let v: serde_json::Value = serde_json::from_str(json_text).map_err(|e| format!("快照 JSON 不合法：{}", e))?;
    let mut diags = Vec::new();
    let mut dlls = Vec::new();
    let arr = v.get("dlls").and_then(|x| x.as_array()).ok_or("快照缺少 dlls 数组")?;
    for (di, d) in arr.iter().enumerate() {
        let name = d.get("name").and_then(|x| x.as_str()).unwrap_or("<unnamed>").to_string();
        let base = parse_hex_field(d.get("image_base")).unwrap_or_else(|| {
            diags.push(format!("SNAPSHOT_BAD_IMAGE_BASE dll={} 原始值保留未转换", name));
            0
        });
        let mut exports = Vec::new();
        if let Some(exs) = d.get("exports").and_then(|x| x.as_array()) {
            for (ei, e) in exs.iter().enumerate() {
                let ename = e.get("name").and_then(|x| x.as_str()).map(String::from);
                let ordinal = e.get("ordinal").and_then(|x| x.as_u64()).map(|x| x as u16);
                let rva_value = parse_hex_field(e.get("rva"));
                if rva_value.is_none() {
                    diags.push(format!(
                        "SNAPSHOT_BAD_RVA dll={} ordinal={:?} name={:?} rva 原始表示保留，无法转换",
                        name, ordinal, ename));
                }
                let forwarder = e.get("forwarder").and_then(|x| x.as_str()).map(String::from);
                exports.push(ExportEntry {
                    name: ename, ordinal, rva_value, forwarder,
                    record_ref: format!("{}#dll[{}]#export[{}]", source_id, di, ei),
                });
            }
        }
        dlls.push(DllSnapshot { name, image_base: base, exports });
    }
    Ok((dlls, diags))
}

fn parse_hex_field(v: Option<&serde_json::Value>) -> Option<u64> {
    let s = v?.get("value")?.as_str()?;
    let t = s.trim();
    let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    u64::from_str_radix(t, 16).ok()
}

pub const RULE_VERSION: &str = "rules-1.0.0";

pub fn build_intervals(facts: &PeFacts) -> Vec<SectionInterval> {
    facts.sections.iter().map(|s| {
        let vs = s.virtual_size.value.unwrap_or(0);
        let va = s.virtual_address.value.unwrap_or(0);
        let rs = s.size_of_raw_data.value.unwrap_or(0);
        let rp = s.pointer_to_raw_data.value;
        let raw_cov = rs.min(vs);
        SectionInterval {
            section_id: format!("sec/{}", s.ordinal),
            name: s.name.clone(),
            ordinal: s.ordinal,
            virtual_start: va,
            virtual_end: va + vs,
            raw_start: rp,
            raw_end: rp.map(|p| p + raw_cov),
            raw_virtual_gap: vs > rs,
        }
    }).collect()
}

/// RVA -> 候选集合。重叠时返回每个提供 raw 的节候选；
/// 落在虚拟区间但超过 raw 范围时给 ZERO_FILL 候选；完全无覆盖给单个 UNMAPPED。
pub fn map_rva(rva: u32, facts: &PeFacts) -> Vec<MappingCandidate> {
    let mut out = Vec::new();
    for s in &facts.sections {
        let va = match s.virtual_address.value { Some(v) => v, None => continue };
        let vs = match s.virtual_size.value { Some(v) => v, None => continue };
        if rva < va || rva >= va + vs { continue; }
        let d = rva - va;
        let rs = s.size_of_raw_data.value.unwrap_or(0);
        let rp = s.pointer_to_raw_data.value;
        if d < rs {
            if let Some(p) = rp {
                out.push(MappingCandidate {
                    kind: "MAPPED_RAW".into(),
                    section_id: Some(format!("sec/{}", s.ordinal)),
                    section_name: Some(s.name.clone()),
                    file_offset: Some(p + d),
                    basis: "rva32->file-offset via section raw",
                    note: format!("节 {} 内 [raw+0x{:X}]", s.name, d),
                });
            }
        } else {
            out.push(MappingCandidate {
                kind: "ZERO_FILL".into(),
                section_id: Some(format!("sec/{}", s.ordinal)),
                section_name: Some(s.name.clone()),
                file_offset: None,
                basis: "rva32 in virtual-only tail (virtual size > raw size)",
                note: format!("节 {} 虚拟尾部 +0x{:X}，无文件字节，按零填充", s.name, d),
            });
        }
    }
    if out.is_empty() {
        out.push(MappingCandidate {
            kind: "UNMAPPED".into(),
            section_id: None,
            section_name: None,
            file_offset: None,
            basis: "rva32 with no covering section",
            note: "没有任何节覆盖该 RVA".into(),
        });
    }
    out
}

fn read_candidate_bytes(b: &[u8], cand: &MappingCandidate, width: usize) -> Option<u64> {
    let fo = cand.file_offset? as usize;
    if fo + width > b.len() { return None; }
    let mut v = 0u64;
    for k in 0..width { v |= (b[fo + k] as u64) << (8 * k); }
    Some(v)
}

pub fn derive(facts: &PeFacts, bytes: &[u8], image_base: u64, snapshots: &[DllSnapshot]) -> DerivedView {
    let sections = build_intervals(facts);
    let delta = image_base.wrapping_sub(facts.opt.image_base.value.unwrap_or(0));

    let mut reloc_patches = Vec::new();
    for blk in &facts.reloc_blocks {
        for e in &blk.entries {
            let rid = format!("reloc/{}/{}", blk.index, e.index);
            if e.type_name == "ABSOLUTE" {
                reloc_patches.push(RelocPatch {
                    reloc_id: rid, block_index: blk.index, entry_index: e.index,
                    type_name: e.type_name.clone(), width_bytes: 0, target_rva: e.rva,
                    original_value: None, patched_value: None,
                    status: "NOT_APPLICABLE".into(), candidates: vec![],
                    diagnostic_code: None, message: "ABSOLUTE 填充条目，不产生补丁".into(),
                });
                continue;
            }
            let cands = map_rva(e.rva, facts);
            let any_raw = cands.iter().any(|c| c.kind == "MAPPED_RAW");
            let zerofill = cands.iter().any(|c| c.kind == "ZERO_FILL");
            let unmapped = cands.iter().all(|c| c.kind == "UNMAPPED");

            if unmapped {
                reloc_patches.push(RelocPatch {
                    reloc_id: rid, block_index: blk.index, entry_index: e.index,
                    type_name: e.type_name.clone(), width_bytes: e.width_bytes, target_rva: e.rva,
                    original_value: None, patched_value: None,
                    status: "UNMAPPED_TARGET".into(), candidates: cands,
                    diagnostic_code: Some("RELOC_TARGET_NO_MAPPING".into()),
                    message: format!("重定位目标 RVA 0x{:08X} 无任何节映射，不写补丁", e.rva),
                });
                continue;
            }
            if matches!(e.type_name.as_str(), "UNKNOWN" | "HIGHADJ_CLASS" | "HIGH3ADJ") {
                reloc_patches.push(RelocPatch {
                    reloc_id: rid, block_index: blk.index, entry_index: e.index,
                    type_name: e.type_name.clone(), width_bytes: e.width_bytes, target_rva: e.rva,
                    original_value: None, patched_value: None,
                    status: "UNSUPPORTED".into(), candidates: cands,
                    diagnostic_code: Some("RELOC_TYPE_UNSUPPORTED".into()),
                    message: format!("重定位类型 {} 不单独执行，原始条目保留", e.type_name),
                });
                continue;
            }

            let target_va = (image_base as u128) + (e.rva as u128);
            let width = e.width_bytes as u32;
            let maxv = if width >= 8 { u128::MAX } else { (1u128 << (width * 8)) - 1 };
            let overflow = target_va > maxv;

            let mut annotated = Vec::new();
            for cand in &cands {
                let orig = match cand.kind.as_str() {
                    "MAPPED_RAW" => read_candidate_bytes(bytes, cand, e.width_bytes as usize),
                    "ZERO_FILL" => Some(0u64),
                    _ => None,
                };
                let mut c2 = cand.clone();
                let orig_txt = match (cand.kind.as_str(), e.width_bytes) {
                    ("MAPPED_RAW", 4) => orig.map(|v| format!("0x{:08X}", v as u32)),
                    ("MAPPED_RAW", 8) => orig.map(|v| format!("0x{:016X}", v)),
                    ("ZERO_FILL", _) => Some("0x0 (zero-fill)".into()),
                    _ => None,
                };
                c2.note = format!("{}；原始值 {}；delta=0x{:X}", c2.note,
                    orig_txt.unwrap_or_else(|| "<unavailable>".into()), delta);
                annotated.push(c2);
            }

            let status = if overflow { "OVERFLOW" }
                else if !any_raw && zerofill { "ZERO_FILL" }
                else { "PATCHED" };

            reloc_patches.push(RelocPatch {
                reloc_id: rid, block_index: blk.index, entry_index: e.index,
                type_name: e.type_name.clone(), width_bytes: e.width_bytes, target_rva: e.rva,
                original_value: Some("per-candidate original bytes kept on candidates".into()),
                patched_value: if overflow { None }
                    else if e.width_bytes == 8 { Some(format!("0x{:016X}", target_va as u64)) }
                    else { Some(format!("0x{:08X}", target_va as u32)) },
                status: status.into(),
                candidates: annotated,
                diagnostic_code: if overflow { Some("RELOC_VALUE_OVERFLOW".into()) } else { None },
                message: if overflow {
                    format!("{} 重定位目标 VA 0x{:X} 超出 {} 位无符号范围，拒绝补丁",
                            e.type_name, target_va, e.width_bytes * 8)
                } else {
                    format!("{} 补丁可应用，delta=0x{:X}，目标 VA=0x{:X}", e.type_name, delta, target_va)
                },
            });
        }
    }

    let mut imports = Vec::new();
    let by_name: BTreeMap<String, &DllSnapshot> =
        snapshots.iter().map(|d| (d.name.to_lowercase(), d)).collect();
    for desc in &facts.imports {
        for th in &desc.thunks {
            let iid = format!("import/{}/{}", desc.index, th.index);
            let snap = by_name.get(&desc.dll_name.to_lowercase()).copied();
            imports.push(bind_one(snap, desc.dll_name.clone(), th, iid, desc.index, snapshots));
        }
    }

    DerivedView {
        rule_version: RULE_VERSION.into(),
        image_base_used: format!("0x{:016X}", image_base),
        sections,
        reloc_patches,
        imports,
    }
}

use crate::pe_parser::{ImportDescriptor, ImportThunk};

fn find_export<'a>(snap: &'a DllSnapshot, th: &ImportThunk) -> Option<&'a ExportEntry> {
    snap.exports.iter().find(|e| {
        if th.is_ordinal {
            th.ordinal.and_then(|o| e.ordinal.map(|eo| eo == o)).unwrap_or(false)
        } else {
            th.name.as_ref().and_then(|n| e.name.as_ref().map(|en| en == n)).unwrap_or(false)
        }
    })
}

fn split_forwarder(f: &str) -> (String, String) {
    // 形如 MODULE.Symbol 或 MODULE.#ordinal
    if let Some((m, s)) = f.split_once('.') {
        (m.to_string(), s.to_string())
    } else {
        (f.to_string(), String::new())
    }
}

fn bind_one(snap: Option<&DllSnapshot>, dll_name: String, th: &ImportThunk,
            iid: String, descriptor_index: usize, snapshots: &[DllSnapshot]) -> ImportBinding {
    let base_msg = format!("{} 的 thunk#{}", dll_name, th.index);
    let Some(snap) = snap else {
        return ImportBinding {
            import_id: iid, descriptor_index, thunk_index: th.index,
            dll_name, by_ordinal: th.is_ordinal, ordinal: th.ordinal,
            symbol_name: th.name.clone(),
            status: "UNRESOLVED_MISSING_DLL".into(),
            resolved_va: None, forward_chain: vec![], source_export: None,
            message: format!("{}：缺少该 DLL 的导出快照，只记录 unresolved import，不伪造绑定", base_msg),
        };
    };

    let Some(entry) = find_export(snap, th) else {
        return ImportBinding {
            import_id: iid, descriptor_index, thunk_index: th.index,
            dll_name, by_ordinal: th.is_ordinal, ordinal: th.ordinal,
            symbol_name: th.name.clone(),
            status: "UNRESOLVED_MISSING_EXPORT".into(),
            resolved_va: None, forward_chain: vec![],
            source_export: None,
            message: format!("{}：{} 中找不到对应导出，保留为 unresolved", base_msg, snap.name),
        };
    };
    if entry.rva_value.is_none() {
        return ImportBinding {
            import_id: iid, descriptor_index, thunk_index: th.index,
            dll_name, by_ordinal: th.is_ordinal, ordinal: th.ordinal,
            symbol_name: th.name.clone(),
            status: "UNRESOLVED_MALFORMED_EXPORT".into(),
            resolved_va: None, forward_chain: vec![],
            source_export: Some(entry.record_ref.clone()),
            message: format!("{}：导出记录 {} 的 RVA 无法转换，原始表示保留，不绑定地址", base_msg, entry.record_ref),
        };
    }

    let mut chain = Vec::new();
    // 处理转发：沿 forwarder 链在给定快照集合内解析，链中缺快照只产生 unresolved
    let mut cur_dll = snap.clone();
    let mut cur_entry = entry;
    loop {
        chain.push(format!("{}!{}", cur_dll.name,
            cur_entry.name.clone().unwrap_or_else(|| format!("#{:?}", cur_entry.ordinal))));
        if let Some(fwd) = &cur_entry.forwarder {
            let (fmod, fsym) = split_forwarder(fwd);
            let fmod_dll = format!("{}.dll", fmod);
            let Some(next) = snapshots.iter().find(|d| d.name.eq_ignore_ascii_case(&fmod_dll)) else {
                return ImportBinding {
                    import_id: iid, descriptor_index, thunk_index: th.index,
                    dll_name, by_ordinal: th.is_ordinal, ordinal: th.ordinal,
                    symbol_name: th.name.clone(),
                    status: "UNRESOLVED_FORWARDER_MISSING_DLL".into(),
                    resolved_va: None, forward_chain: chain,
                    source_export: Some(entry.record_ref.clone()),
                    message: format!("{}：转发 {} 需要 {} 快照但未提供，unresolved", base_msg, fwd, fmod_dll),
                };
            };
            let next_entry = next.exports.iter().find(|e| e.name.as_deref() == Some(fsym.as_str())
                || fsym.strip_prefix('#').and_then(|x| x.parse::<u16>().ok())
                    .and_then(|o| e.ordinal.map(|eo| eo == o)).unwrap_or(false));
            match next_entry {
                Some(ne) => { cur_dll = next.clone(); cur_entry = ne; }
                None => return ImportBinding {
                    import_id: iid, descriptor_index, thunk_index: th.index,
                    dll_name, by_ordinal: th.is_ordinal, ordinal: th.ordinal,
                    symbol_name: th.name.clone(),
                    status: "UNRESOLVED_FORWARDER_MISSING_EXPORT".into(),
                    resolved_va: None, forward_chain: chain,
                    source_export: Some(entry.record_ref.clone()),
                    message: format!("{}：转发 {} 在 {} 中无对应导出，unresolved", base_msg, fwd, next.name),
                },
            }
        } else {
            let va = cur_dll.image_base.checked_add(cur_entry.rva_value.unwrap_or(0));
            let forwarded = !chain.is_empty() && cur_dll.name != snap.name;
            return ImportBinding {
                import_id: iid, descriptor_index, thunk_index: th.index,
                dll_name, by_ordinal: th.is_ordinal, ordinal: th.ordinal,
                symbol_name: th.name.clone(),
                status: if forwarded { "RESOLVED_FORWARDED".into() } else { "RESOLVED".into() },
                resolved_va: va.map(|x| format!("0x{:016X}", x)),
                forward_chain: chain,
                source_export: Some(cur_entry.record_ref.clone()),
                message: format!("{}：绑定到 {} + RVA 0x{:X}", base_msg, cur_dll.name,
                                 cur_entry.rva_value.unwrap_or(0)),
            };
        }
    }
}

#[allow(dead_code)]
fn keep_import_type(_: &ImportDescriptor) {}
