//! 装载语义推导层：在材料之上派生，保留多候选，不做不可逆选择。
//!
//! 判断依据（全部写入候选的 `basis`，机器可读）：
//! - RVA→文件偏移：无映射 / 多节重叠 / 仅零填充 均保留为候选，不强行选一。
//! - 重定位：按 type 与位宽执行；溢出/越界产出诊断候选，不静默丢弃。
//! - 缺失 DLL：只产生 unresolved import，不猜地址。

use crate::model::{ByteSource, Diagnostic, Material, RuleSet};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Candidate {
    pub id: String,
    pub kind: String, // mapped | overlap | zero_fill | unmapped | overflow | unresolved | bound | forwarded
    pub label: String,
    pub value: serde_json::Value,
    pub valid: bool,
    pub basis: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Fact {
    pub id: String,
    pub kind: String, // section_map | rva_resolution | reloc_patch | import_binding | image_summary
    pub subject: String,
    pub ordinal: i64,
    pub status: String, // multi_candidate | unique | unresolved | error | informational
    pub candidates: Vec<Candidate>,
    pub deps: Vec<String>,
    pub evidence: Vec<ByteSource>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AnalysisResult {
    pub facts: Vec<Fact>,
    /// 所有被依赖的输入键：`material:<id>` / `ruleset:<id>`。
    pub input_keys: Vec<String>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone)]
struct SectInfo {
    index: usize,
    name: String,
    vsize: i64,
    vaddr: i64,
    rsize: i64,
    rptr: i64,
}

fn num(payload: &serde_json::Value, path: &str) -> Option<i64> {
    payload.pointer(path).and_then(|v| v.get("value")).and_then(|v| v.as_i64())
}

pub fn analyze(materials: &[Material], rules: &RuleSet, file_len: i64) -> AnalysisResult {
    let mut facts = Vec::new();
    let mut input_keys: Vec<String> = vec![format!("ruleset:{}", rules.id)];
    for m in materials {
        input_keys.push(format!("material:{}", m.id));
    }
    let mut ord = 0i64;
    let mut next = |facts: &mut Vec<Fact>, ord: &mut i64| { *ord += 1; *ord };

    let nt = materials.iter().find(|m| m.kind == "nt_header");
    let expected_base = nt.and_then(|m| num(&m.payload, "/expected_image_base")).unwrap_or(0);
    let header_base = nt.and_then(|m| num(&m.payload, "/image_base_header")).unwrap_or(0);
    let size_of_image = nt.and_then(|m| num(&m.payload, "/size_of_image")).unwrap_or(0);

    // ---- 节材料 ----
    let sections: Vec<SectInfo> = materials.iter().filter(|m| m.kind == "section_header")
        .map(|m| SectInfo {
            index: m.pointer("/index").and_then(|v| v.as_i64()).unwrap_or(0) as usize,
            name: m.pointer("/name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            vsize: num(&m.payload, "/virtual_size").unwrap_or(0),
            vaddr: num(&m.payload, "/virtual_address").unwrap_or(0),
            rsize: num(&m.payload, "/size_of_raw_data").unwrap_or(0),
            rptr: num(&m.payload, "/pointer_to_raw_data").unwrap_or(0),
        }).collect();
    let pe_art = materials.first().map(|m| m.id.split(":mat:").next().unwrap_or("pe")).unwrap_or("pe");

    // ---- 节映射事实（含 virtual>raw 零填充、raw 越 EOF、virtual 重叠）----
    for s in &sections {
        let mapped = s.vsize.min(s.rsize).min((file_len - s.rptr).max(0)).max(0);
        let zero_fill = (s.vsize - mapped).max(0);
        let overlap_with: Vec<&SectInfo> = sections.iter().filter(|o| o.index != s.index
            && s.vaddr < o.vaddr + o.vsize && o.vaddr < s.vaddr + s.vsize).collect();
        let mut cands = Vec::new();
        cands.push(Candidate {
            id: format!("fact-sec-{}-mapped", s.index), kind: "mapped".into(),
            label: format!("{} 原始字节映射", s.name), valid: true,
            value: json!({"file_offset": s.rptr, "mapped_bytes": mapped, "unit": "byte"}),
            basis: "mapped_bytes = min(virtual_size, raw_size, EOF - raw_ptr)".into(),
        });
        if zero_fill > 0 {
            cands.push(Candidate {
                id: format!("fact-sec-{}-zerofill", s.index), kind: "zero_fill".into(),
                label: format!("{} 零填充区间 (virtual size > raw)", s.name), valid: true,
                value: json!({"zero_fill_rva": s.vaddr + mapped, "zero_fill_bytes": zero_fill, "unit": "byte"}),
                basis: "bytes beyond raw size inside virtual size are loader zero-fill, not file content".into(),
            });
        }
        for o in &overlap_with {
            cands.push(Candidate {
                id: format!("fact-sec-{}-overlap-{}", s.index, o.index), kind: "overlap".into(),
                label: format!("{} 与 {} 虚拟区间重叠", s.name, o.name), valid: true,
                value: json!({"other_section": o.name,
                    "overlap_start_rva": s.vaddr.max(o.vaddr),
                    "overlap_end_rva": (s.vaddr + s.vsize).min(o.vaddr + o.vsize), "unit": "rva"}),
                basis: "virtual ranges intersect: RVA resolution must keep all covering sections as candidates".into(),
            });
        }
        let status = if cands.iter().filter(|c| c.kind == "overlap").count() > 0 || zero_fill > 0 {
            "multi_candidate"
        } else { "unique" };
        let n = next(&mut facts, &mut ord);
        facts.push(Fact {
            id: format!("{pe_art}:fact:section_map:{:03}:{}", n, s.name),
            kind: "section_map".into(), subject: s.name.clone(), ordinal: n, status: status.into(),
            candidates: cands,
            deps: section_deps(materials, s.index),
            evidence: section_evidence(materials, s.index),
            diagnostics: section_diagnostics(materials, s.index),
        });
    }

    // ---- 显式探针：无映射 / 重叠 / 零填充 三类 RVA 解析（来自规则参数）----
    let probes = rules.params.get("rva_probes").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    for (i, probe) in probes.iter().enumerate() {
        let rva = probe.get("rva").and_then(|v| v.as_i64()).unwrap_or(0);
        let len = probe.get("len_bytes").and_then(|v| v.as_i64()).unwrap_or(8);
        let label = probe.get("label").and_then(|v| v.as_str()).unwrap_or("probe").to_string();
        let cands = resolve_rva_candidates(&sections, rva, len, file_len);
        let status = match cands.len() {
            0 => "unmapped".into(),
            1 if cands[0].kind == "zero_fill" => "multi_candidate".into(),
            1 => "unique".into(),
            _ => "multi_candidate".into(),
        };
        let n = next(&mut facts, &mut ord);
        facts.push(Fact {
            id: format!("{pe_art}:fact:rva_resolution:{n:03}"),
            kind: "rva_resolution".into(),
            subject: format!("probe[{i}]:{label}@0x{rva:X}"), ordinal: n, status,
            candidates: cands,
            deps: vec![format!("ruleset:{}", rules.id)],
            evidence: vec![], diagnostics: vec![],
        });
    }

    // ---- image base 差异（决定重定位 delta）----
    let delta = expected_base.wrapping_sub(header_base) as i64;
    let base_cands = if delta == 0 {
        vec![Candidate {
            id: "base-delta-zero".into(), kind: "mapped".into(),
            label: "image base 与预期一致，delta=0".into(), valid: true,
            value: json!({"delta": 0, "unit": "byte"}),
            basis: "delta = expected_image_base - optional_header.image_base".into(),
        }]
    } else {
        vec![Candidate {
            id: "base-delta-nonzero".into(), kind: "mapped".into(),
            label: "image base 重定基".into(), valid: true,
            value: json!({"delta": delta, "unit": "byte",
                          "expected_base": expected_base, "header_base": header_base}),
            basis: "delta = expected_image_base - optional_header.image_base".into(),
        }]
    };
    let n = next(&mut facts, &mut ord);
    facts.push(Fact {
        id: format!("{pe_art}:fact:image_summary:{n:03}"),
        kind: "image_summary".into(), subject: "image_base".into(), ordinal: n,
        status: "informational".into(), candidates: base_cands,
        deps: vec![format!("ruleset:{}", rules.id)], evidence: vec![], diagnostics: vec![],
    });

    analyze_relocations(&mut facts, &mut ord, materials, &sections, rules, pe_art, delta, size_of_image);
    analyze_imports(&mut facts, &mut ord, materials, rules, pe_art, expected_base);

    AnalysisResult { facts, input_keys, diagnostics: Vec::new() }
}

fn section_deps(materials: &[Material], index: usize) -> Vec<String> {
    materials.iter().filter(|m| m.kind == "section_header"
        && m.pointer("/index").and_then(|v| v.as_i64()) == Some(index as i64))
        .map(|m| format!("material:{}", m.id)).collect()
}
fn section_evidence(materials: &[Material], index: usize) -> Vec<ByteSource> {
    materials.iter().filter(|m| m.kind == "section_header"
        && m.pointer("/index").and_then(|v| v.as_i64()) == Some(index as i64))
        .flat_map(|m| m.byte_sources.clone()).collect()
}
fn section_diagnostics(materials: &[Material], index: usize) -> Vec<Diagnostic> {
    materials.iter().filter(|m| m.kind == "section_header"
        && m.pointer("/index").and_then(|v| v.as_i64()) == Some(index as i64))
        .flat_map(|m| m.diagnostics.clone()).collect()
}

/// RVA→偏移候选。重叠节全部保留；raw 之外只给 zero_fill；无节覆盖给 unmapped 候选。
fn resolve_rva_candidates(sections: &[SectInfo], rva: i64, len: i64, file_len: i64) -> Vec<Candidate> {
    let covering: Vec<&SectInfo> = sections.iter().filter(|s| {
        rva >= s.vaddr && rva + len <= s.vaddr + s.vsize.max(0)
    }).collect();
    if covering.is_empty() {
        return vec![Candidate {
            id: format!("unmapped@0x{rva:X}"), kind: "unmapped".into(),
            label: format!("RVA 0x{rva:X} 无映射"), valid: false,
            value: json!({"rva": rva, "len_bytes": len}),
            basis: "no section virtual range covers [rva, rva+len); no forced choice".into(),
        }];
    }
    let mut out = Vec::new();
    for s in covering {
        let inner = rva - s.vaddr;
        let mapped_raw = s.rsize.min(s.vsize).min((file_len - s.rptr).max(0));
        if inner < mapped_raw && inner + len <= mapped_raw {
            out.push(Candidate {
                id: format!("map:{}@0x{rva:X}", s.name), kind: "mapped".into(),
                label: format!("{} -> 文件偏移 0x{:X}", s.name, s.rptr + inner), valid: true,
                value: json!({"section": s.name, "file_offset": s.rptr + inner, "len_bytes": len, "unit": "byte"}),
                basis: "file_offset = pointer_to_raw_data + (rva - virtual_address)".into(),
            });
        } else {
            out.push(Candidate {
                id: format!("zerofill:{}@0x{rva:X}", s.name), kind: "zero_fill".into(),
                label: format!("{} 仅零填充（virtual size > raw）", s.name), valid: true,
                value: json!({"section": s.name, "rva": rva, "len_bytes": len}),
                basis: "offset lies inside virtual size but beyond mapped raw size: loader zero-fill only".into(),
            });
        }
    }
    out
}

fn analyze_relocations(facts: &mut Vec<Fact>, ord: &mut i64, materials: &[Material],
                       sections: &[SectInfo], rules: &RuleSet, pe_art: &str, delta: i64,
                       size_of_image: i64) {
    let Some(reloc_mat) = materials.iter().find(|m| m.kind == "relocation_table") else { return };
    let Some(blocks) = reloc_mat.pointer("/blocks").and_then(|v| v.as_array()) else { return };
    let mut idx = 0i64;
    for block in blocks {
        let page = block.pointer("/page_rva/value").and_then(|v| v.as_i64()).unwrap_or(0);
        for entry in block.pointer("/entries").and_then(|v| v.as_array()).unwrap_or(&Vec::new()) {
            let kind = entry.get("type").and_then(|v| v.as_i64()).unwrap_or(0);
            if kind == 0 { continue; } // ABSOLUTE 填充
            let off = entry.pointer("/offset/value").and_then(|v| v.as_i64()).unwrap_or(0);
            let target_rva = page + off;
            let width_bits = match kind { 3 => 32, 10 => 64, 1 | 2 => 16, _ => 0 };
            let width_bytes = width_bits / 8;
            let cover: Vec<&SectInfo> = sections.iter().filter(|s|
                target_rva >= s.vaddr && target_rva + width_bytes <= s.vaddr + s.vsize).collect();

            let mut cands = Vec::new();
            let mut status = String::from("unique");

            if width_bits == 0 {
                cands.push(Candidate {
                    id: format!("reloc-{idx}-unsupported"), kind: "unresolved".into(),
                    label: format!("重定位类型 {} 未实现", crate::pe::reloc_type_name(kind)),
                    valid: false,
                    value: json!({"reloc_type": kind, "target_rva": target_rva}),
                    basis: "only HIGH(1)/LOW(2)/HIGHLOW(3)/DIR64(10) are applied by type and width".into(),
                });
                status = "error".into();
            } else if cover.is_empty() {
                cands.push(Candidate {
                    id: format!("reloc-{idx}-overflow-oob"), kind: "overflow".into(),
                    label: format!("重定位目标 RVA 0x{target_rva:X} 超出任何节（溢出）"),
                    valid: false,
                    value: json!({"reloc_type": kind, "width_bits": width_bits,
                                  "target_rva": target_rva, "size_of_image_rva": size_of_image}),
                    basis: "patch target not contained in any mapped section: relocation overflow, patch not applied".into(),
                });
                status = "error".into();
            } else {
                for s in &cover {
                    let inner = target_rva - s.vaddr;
                    let file_offset = s.rptr + inner;
                    // 按位宽计算补丁：HIGHLOW 结果必须可表示为 32 位。
                    let (patched, overflow) = match kind {
                        3 => {
                            let wrapped = (delta as i128) & 0xFFFF_FFFF;
                            let signed = if wrapped >= 0x8000_0000 { wrapped - 0x1_0000_0000 } else { wrapped };
                            (signed as i64, signed != signed as i32 as i128)
                        }
                        10 => {
                            let target_va = rules.params.get("expected_image_base")
                                .and_then(|v| v.as_i64()).unwrap_or(0) as i128
                                + target_rva as i128;
                            let ov = !(0..=0xFFFF_FFFF_FFFF_FFFF).contains(&target_va);
                            (((delta as u64) as i64) & 0xFFFF_FFFF_FFFF_FFFF, ov)
                        }
                        _ => (delta & 0xFFFF, false),
                    };
                    if overflow {
                        cands.push(Candidate {
                            id: format!("reloc-{idx}-overflow-{name}", name = s.name),
                            kind: "overflow".into(),
                            label: format!("{name} 处 {ty} 补丁算术溢出", name = s.name, ty = crate::pe::reloc_type_name(kind)),
                            valid: false,
                            value: json!({"section": s.name, "file_offset": file_offset,
                                          "width_bits": width_bits, "delta": delta, "target_rva": target_rva}),
                            basis: "patch result does not fit the relocation width: overflow candidate retained, not applied".into(),
                        });
                        status = "error".into();
                    } else {
                        cands.push(Candidate {
                            id: format!("reloc-{idx}-patch-{name}", name = s.name), kind: "mapped".into(),
                            label: format!("{name} 处 {ty} 补丁", name = s.name, ty = crate::pe::reloc_type_name(kind)),
                            valid: true,
                            value: json!({"section": s.name, "file_offset": file_offset, "unit": "byte",
                                          "target_rva": target_rva, "width_bits": width_bits,
                                          "addend": delta, "patched_value": patched}),
                            basis: "add (expected_base - header_base) with width/endianness of reloc type".into(),
                        });
                    }
                }
                if cover.len() > 1 { status = "multi_candidate".into(); }
            }
            *ord += 1;
            facts.push(Fact {
                id: format!("{pe_art}:fact:reloc_patch:{ord:03}"),
                kind: "reloc_patch".into(),
                subject: format!("{}@0x{target_rva:08X}", crate::pe::reloc_type_name(kind)),
                ordinal: *ord, status, candidates: cands,
                deps: vec![
                    format!("ruleset:{}", rules.id),
                    reloc_mat.id.clone(),
                ],
                evidence: reloc_mat.byte_sources.clone(),
                diagnostics: reloc_mat.diagnostics.clone(),
            });
            idx += 1;
        }
    }
}

#[derive(Debug, Clone)]
struct ExportEntry {
    dll: String,
    name: Option<String>,
    ordinal: Option<i64>,
    forwarder: Option<String>,
    rva: i64,
}

fn collect_exports(materials: &[Material]) -> (Vec<ExportEntry>, Vec<String>, Vec<String>) {
    let mut entries = Vec::new();
    let mut dlls = Vec::new();
    let mut corrupt = Vec::new();
    for m in materials.iter().filter(|m| m.kind == "export_snapshot") {
        let dll = m.pointer("/dll").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if !dll.is_empty() && !dlls.contains(&dll) { dlls.push(dll.clone()); }
        if m.pointer("/corrupt_range").and_then(|v| v.as_bool()).unwrap_or(false) {
            corrupt.push(format!("{dll}#{}", m.ordinal));
        }
        if let Some(arr) = m.pointer("/exports").and_then(|v| v.as_array()) {
            for e in arr {
                entries.push(ExportEntry {
                    dll: dll.clone(),
                    name: e.get("name").and_then(|v| v.as_str()).map(str::to_string),
                    ordinal: e.get("ordinal").and_then(|v| v.as_i64()),
                    forwarder: e.get("forwarder").and_then(|v| v.as_str()).map(str::to_string),
                    rva: e.get("rva").and_then(|v| v.as_i64()).unwrap_or(0),
                });
            }
        }
    }
    (entries, dlls, corrupt)
}

fn analyze_imports(facts: &mut Vec<Fact>, ord: &mut i64, materials: &[Material],
                   rules: &RuleSet, pe_art: &str, expected_base: i64) {
    let Some(import_mat) = materials.iter().find(|m| m.kind == "import_table") else { return };
    let (exports, dlls, corrupt_dlls) = collect_exports(materials);
    let descriptors = import_mat.pointer("/descriptors").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let available_dlls: Vec<String> = rules.params.get("available_dlls")
        .and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_else(|| dlls.clone());

    for thunk in import_mat.pointer("/thunks").and_then(|v| v.as_array()).unwrap_or(&Vec::new()) {
        let dll = thunk.get("dll_name").and_then(|v| v.as_str()).unwrap_or("");
        let idx = thunk.get("index").and_then(|v| v.as_i64()).unwrap_or(0);
        let thunk_rva = thunk.pointer("/thunk_rva/value").and_then(|v| v.as_i64()).unwrap_or(0);
        let import_by = thunk.get("import_by").and_then(|v| v.as_str()).unwrap_or("name");
        let mut cands = Vec::new();
        let mut status = String::from("unique");
        let mut deps = vec![import_mat.id.clone(), format!("ruleset:{}", rules.id)];

        let dll_present = available_dlls.iter().any(|d| d.eq_ignore_ascii_case(dll));
        if !dll_present {
            cands.push(Candidate {
                id: format!("import-{dll}-{idx}-missing"), kind: "unresolved".into(),
                label: format!("{dll} 缺失：unresolved import"), valid: false,
                value: json!({"dll": dll, "import_by": import_by, "thunk_rva": thunk_rva,
                              "name": thunk.get("name"), "ordinal": thunk.get("ordinal")}),
                basis: "missing DLL produces unresolved import only; no address is guessed".into(),
            });
            status = "unresolved".into();
        } else if corrupt_dlls.iter().any(|c| c.split('#').next().unwrap_or("").eq_ignore_ascii_case(dll)) {
            cands.push(Candidate {
                id: format!("import-{dll}-{idx}-corrupt-export-dir"), kind: "unresolved".into(),
                label: format!("{dll} export directory 范围损坏，无法绑定"), valid: false,
                value: json!({"dll": dll, "reason": "corrupt_export_directory_range"}),
                basis: "export data directory range is corrupt: bindings cannot be resolved, diagnostics retained".into(),
            });
            status = "error".into();
            if let Some(snap) = materials.iter().find(|m| m.kind == "export_snapshot"
                && m.pointer("/dll").and_then(|v| v.as_str()).map(|d| d.eq_ignore_ascii_case(dll)).unwrap_or(false)) {
                deps.push(snap.id.clone());
            }
        } else {
            let matches: Vec<&ExportEntry> = exports.iter().filter(|e| e.dll.eq_ignore_ascii_case(dll)
                && match import_by {
                    "ordinal" => e.ordinal == thunk.get("ordinal").and_then(|v| v.as_i64()),
                    _ => e.name.as_deref() == thunk.get("name").and_then(|v| v.as_str()),
                }).collect();
            for e in &matches {
                deps.push(format!("export:{}:{}", e.dll,
                    e.name.clone().unwrap_or_else(|| format!("ordinal#{}", e.ordinal.unwrap_or(-1)))));
                if let Some(fwd) = &e.forwarder {
                    cands.push(Candidate {
                        id: format!("import-{dll}-{idx}-forwarded"), kind: "forwarded".into(),
                        label: format!("{dll}!{} 转发到 {fwd}", e.name.clone().unwrap_or_default()),
                        valid: true,
                        value: json!({"dll": dll, "resolved_export": e.name, "forwarder": fwd,
                                      "resolution": "requires forwarding target snapshot; recorded, not flattened"}),
                        basis: "forwarded export recorded as a forwarding edge; target resolution is a separate binding".into(),
                    });
                } else {
                    cands.push(Candidate {
                        id: format!("import-{dll}-{idx}-bound"), kind: "bound".into(),
                        label: format!("{dll}!{} 已绑定", e.name.clone()
                            .or_else(|| e.ordinal.map(|o| format!("#{o}"))).unwrap_or_default()),
                        valid: true,
                        value: json!({"dll": dll, "name": e.name, "ordinal": e.ordinal,
                                      "export_rva": e.rva, "thunk_va": expected_base + thunk_rva, "unit": "va"}),
                        basis: "bound from export snapshot by exact name or ordinal match".into(),
                    });
                }
            }
            if cands.is_empty() {
                cands.push(Candidate {
                    id: format!("import-{dll}-{idx}-unresolved"), kind: "unresolved".into(),
                    label: format!("{dll} 中找不到导入符号"), valid: false,
                    value: json!({"dll": dll, "import_by": import_by,
                                  "name": thunk.get("name"), "ordinal": thunk.get("ordinal")}),
                    basis: "no matching name/ordinal in export snapshot: unresolved import".into(),
                });
                status = "unresolved".into();
            } else if matches.len() > 1 {
                status = "multi_candidate".into();
            }
        }

        let desc_diag: Vec<Diagnostic> = descriptors.iter()
            .find(|d| d.get("dll_name").and_then(|v| v.as_str()) == Some(dll))
            .map(|_| import_mat.diagnostics.clone()).unwrap_or_default();
        *ord += 1;
        facts.push(Fact {
            id: format!("{pe_art}:fact:import_binding:{ord:03}"),
            kind: "import_binding".into(),
            subject: format!("{dll}!{}", thunk.get("name").and_then(|v| v.as_str())
                .or_else(|| thunk.get("ordinal").map(|_| "<ordinal>")).unwrap_or("?")),
            ordinal: *ord, status, candidates: cands, deps,
            evidence: import_mat.byte_sources.clone(), diagnostics: desc_diag,
        });
    }
}

/// 依赖闭包：给定变更输入键，计算受影响 fact；未命中的 fact 保持不变。
pub fn invalidation_scope(previous: &AnalysisResult, changed_input_keys: &[String])
    -> (Vec<String>, Vec<String>) {
    let mut affected = Vec::new();
    let mut unaffected = Vec::new();
    for f in &previous.facts {
        let hit = f.deps.iter().any(|d| changed_input_keys.iter().any(|c| {
            d == c || d.starts_with(&format!("{c}:")) || c.starts_with(&format!("{d}:"))
        }));
        if hit { affected.push(f.id.clone()) } else { unaffected.push(f.id.clone()) }
    }
    (affected, unaffected)
}

/// 裁定失效：fact 被重新计算后，旧候选若不再存在，其裁定进入失效集合。
pub fn stale_decisions(old: &AnalysisResult, new: &AnalysisResult, decisions: &[String])
    -> Vec<String> {
    let mut stale = Vec::new();
    for fact_id in decisions {
        let old_fact = old.facts.iter().find(|f| &f.id == fact_id);
        let new_fact = new.facts.iter().find(|f| &f.id == fact_id);
        match (old_fact, new_fact) {
            (Some(o), Some(n)) => {
                if o.candidates.iter().any(|c| !n.candidates.iter().any(|nc| nc.id == c.id)) {
                    stale.push(fact_id.clone());
                }
            }
            (Some(_), None) => stale.push(fact_id.clone()),
            _ => {}
        }
    }
    stale
}
