//! Loader semantics: RVA->file mapping (multi-candidate), base relocations
//! applied by type and bit width, and import binding against DLL export
//! snapshots. No irreversible decisions are made here: ambiguity is kept as
//! candidate lists, overflows leave the value in place with a diagnostic,
//! and a missing DLL only yields an unresolved import.

use crate::model::parse_num;
use crate::pe::{rva_to_file_first, PeImage};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize)]
pub struct MappingCandidate {
    pub section: String,
    pub file_offset: u64,
    /// "raw_data" | "zero_fill"
    pub source: String,
}

/// Result of mapping one RVA. `status`: "single" | "ambiguous" |
/// "zero_fill" | "unmapped". All legal candidates are preserved.
#[derive(Clone, Debug, Serialize)]
pub struct RvaMapping {
    pub status: String,
    pub candidates: Vec<MappingCandidate>,
}

pub fn map_rva(pe: &PeImage, rva: u64) -> RvaMapping {
    let mut raw_hits: Vec<MappingCandidate> = Vec::new();
    let mut zero_hits: Vec<MappingCandidate> = Vec::new();
    for s in &pe.sections {
        let va = s.virtual_address as u64;
        let end = va + s.mapped_size();
        if rva >= va && rva < end {
            let off = rva - va;
            if off < s.raw_size as u64 {
                raw_hits.push(MappingCandidate {
                    section: s.name.clone(),
                    file_offset: s.raw_offset as u64 + off,
                    source: "raw_data".into(),
                });
            } else {
                zero_hits.push(MappingCandidate {
                    section: s.name.clone(),
                    file_offset: 0,
                    source: "zero_fill".into(),
                });
            }
        }
    }
    if raw_hits.len() > 1 {
        // Overlapping sections: do not force a choice.
        return RvaMapping { status: "ambiguous".into(), candidates: raw_hits };
    }
    if raw_hits.len() == 1 {
        return RvaMapping { status: "single".into(), candidates: raw_hits };
    }
    if !zero_hits.is_empty() {
        // virtual size > raw size: only zero-filled image bytes exist here.
        return RvaMapping { status: "zero_fill".into(), candidates: zero_hits };
    }
    RvaMapping { status: "unmapped".into(), candidates: vec![] }
}

#[derive(Clone, Debug, Serialize)]
pub struct RelocOutcome {
    pub rva: u64,
    pub file_offset: Option<u64>,
    pub type_name: String,
    pub width_bits: u32,
    pub old_raw: String,
    pub old_value: u64,
    pub delta: i64,
    pub new_value: Option<u64>,
    /// "applied" | "overflow" | "skipped" | "unmapped"
    pub status: String,
    pub note: String,
}

fn reloc_type(t: u8) -> (&'static str, u32) {
    match t {
        0 => ("ABSOLUTE", 0),
        1 => ("HIGH", 16),
        2 => ("LOW", 16),
        3 => ("HIGHLOW", 32),
        4 => ("HIGHADJ", 16),
        10 => ("DIR64", 64),
        _ => ("UNKNOWN", 0),
    }
}

pub fn apply_relocations(pe: &PeImage, bytes: &[u8], image_base: u64) -> Vec<RelocOutcome> {
    let delta = image_base as i128 - pe.image_base as i128;
    let mut out = Vec::new();
    for blk in &pe.reloc_blocks {
        for e in &blk.entries {
            let (tname, width) = reloc_type(e.type_);
            let rva = e.rva as u64;
            if width == 0 {
                out.push(RelocOutcome {
                    rva,
                    file_offset: None,
                    type_name: tname.into(),
                    width_bits: 0,
                    old_raw: String::new(),
                    old_value: 0,
                    delta: delta as i64,
                    new_value: None,
                    status: "skipped".into(),
                    note: if e.type_ == 0 {
                        "padding entry; not applied".into()
                    } else {
                        format!("relocation type {} not applied (recorded only)", e.type_)
                    },
                });
                continue;
            }
            let fo = rva_to_file_first(pe, rva);
            let fo = match fo {
                Some(f) if f + (width as usize / 8) <= bytes.len() => f as u64,
                _ => {
                    out.push(RelocOutcome {
                        rva,
                        file_offset: fo.map(|f| f as u64),
                        type_name: tname.into(),
                        width_bits: width,
                        old_raw: String::new(),
                        old_value: 0,
                        delta: delta as i64,
                        new_value: None,
                        status: "unmapped".into(),
                        note: "relocation target has no file bytes".into(),
                    });
                    continue;
                }
            };
            let nbytes = (width / 8) as usize;
            let mut old: u64 = 0;
            for i in 0..nbytes {
                old |= (bytes[fo as usize + i] as u64) << (8 * i);
            }
            let adj: i128 = match e.type_ {
                1 => delta >> 16,
                2 => delta & 0xFFFF,
                _ => delta,
            };
            let new = old as i128 + adj;
            let max = if width >= 64 { u64::MAX as i128 } else { (1i128 << width) - 1 };
            if new < 0 || new > max {
                // Overflow: value stays in place, diagnostic is attached.
                out.push(RelocOutcome {
                    rva,
                    file_offset: Some(fo),
                    type_name: tname.into(),
                    width_bits: width,
                    old_raw: format!("0x{old:0width$X}", width = nbytes * 2),
                    old_value: old,
                    delta: delta as i64,
                    new_value: None,
                    status: "overflow".into(),
                    note: format!(
                        "relocation overflow: 0x{old:X} + delta 0x{:X} exceeds {width}-bit field; value left in place",
                        adj
                    ),
                });
            } else {
                out.push(RelocOutcome {
                    rva,
                    file_offset: Some(fo),
                    type_name: tname.into(),
                    width_bits: width,
                    old_raw: format!("0x{old:0width$X}", width = nbytes * 2),
                    old_value: old,
                    delta: delta as i64,
                    new_value: Some(new as u64),
                    status: "applied".into(),
                    note: String::new(),
                });
            }
        }
    }
    out
}

#[derive(Clone, Debug, Serialize)]
pub struct ExportEntry {
    pub name: Option<String>,
    pub ordinal: Option<u32>,
    pub rva: Option<u64>,
    /// Raw representation kept when the value cannot be converted.
    pub rva_raw: Option<String>,
    pub forwarder: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExportSnapshot {
    pub dll: String,
    pub image_base: Option<u64>,
    pub image_base_raw: Option<String>,
    pub exports: Vec<ExportEntry>,
    pub diagnostics: Vec<String>,
}

pub fn parse_snapshot(bytes: &[u8]) -> Result<ExportSnapshot, String> {
    let v: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let dll = v["dll"].as_str().ok_or("snapshot missing dll name")?.to_string();
    let mut diagnostics = Vec::new();
    let image_base_raw = v["image_base"].as_str().map(|s| s.to_string());
    let image_base = match &image_base_raw {
        Some(raw) => match parse_num(raw) {
            Some(n) => Some(n),
            None => {
                diagnostics.push(format!(
                    "image_base raw value {raw:?} is not convertible; kept raw"
                ));
                None
            }
        },
        None => None,
    };
    let mut exports = Vec::new();
    if let Some(arr) = v["exports"].as_array() {
        for e in arr {
            let name = e["name"].as_str().map(|s| s.to_string());
            let ordinal = e["ordinal"].as_u64().map(|n| n as u32);
            let forwarder = e["forwarder"].as_str().map(|s| s.to_string());
            let (rva, rva_raw) = match e.get("rva") {
                Some(serde_json::Value::String(s)) => match parse_num(s) {
                    Some(n) => (Some(n), Some(s.clone())),
                    None => {
                        diagnostics.push(format!(
                            "export {:?} rva raw value {s:?} is not convertible; kept raw",
                            name
                        ));
                        (None, Some(s.clone()))
                    }
                },
                Some(serde_json::Value::Number(n)) => {
                    (n.as_u64(), Some(n.to_string()))
                }
                _ => (None, None),
            };
            exports.push(ExportEntry { name, ordinal, rva, rva_raw, forwarder });
        }
    }
    Ok(ExportSnapshot { dll, image_base, image_base_raw, exports, diagnostics })
}

#[derive(Clone, Debug, Serialize)]
pub struct ImportBinding {
    pub dll: String,
    pub label: String,
    pub ordinal: Option<u16>,
    pub name: Option<String>,
    /// "bound" | "forwarded" | "unresolved"
    pub status: String,
    pub target: Option<String>,
    pub address: Option<u64>,
    pub forwarder: Option<String>,
    pub reason: Option<String>,
    pub thunk_rva: u64,
    pub thunk_file_offset: u64,
}

pub fn bind_imports(pe: &PeImage, snaps: &BTreeMap<String, ExportSnapshot>) -> Vec<ImportBinding> {
    let mut out = Vec::new();
    for desc in &pe.imports {
        let key = desc.dll.to_uppercase();
        for t in &desc.thunks {
            let label = match (t.ordinal, &t.name) {
                (Some(o), _) => format!("{}!#{}", desc.dll, o),
                (None, Some(n)) => format!("{}!{}", desc.dll, n),
                _ => format!("{}!<unknown>", desc.dll),
            };
            let base = ImportBinding {
                dll: desc.dll.clone(),
                label: label.clone(),
                ordinal: t.ordinal,
                name: t.name.clone(),
                status: String::new(),
                target: None,
                address: None,
                forwarder: None,
                reason: None,
                thunk_rva: t.thunk_rva as u64,
                thunk_file_offset: t.file_offset,
            };
            let snap = match snaps.get(&key) {
                Some(s) => s,
                None => {
                    // Missing DLL only produces an unresolved import.
                    out.push(ImportBinding {
                        status: "unresolved".into(),
                        reason: Some("dll snapshot missing".into()),
                        ..base
                    });
                    continue;
                }
            };
            let found = snap.exports.iter().find(|e| {
                match (t.ordinal, &t.name) {
                    (Some(o), _) => e.ordinal == Some(o as u32),
                    (None, Some(n)) => e.name.as_deref() == Some(n.as_str()),
                    _ => false,
                }
            });
            match found {
                None => out.push(ImportBinding {
                    status: "unresolved".into(),
                    reason: Some("export not found in snapshot".into()),
                    ..base
                }),
                Some(e) => {
                    if let Some(fwd) = &e.forwarder {
                        let fwd_dll = fwd.split('.').next().unwrap_or("").to_uppercase();
                        let reason = if !fwd_dll.is_empty() && !snaps.contains_key(&fwd_dll) {
                            Some(format!("forward target dll {fwd_dll} snapshot missing"))
                        } else {
                            None
                        };
                        out.push(ImportBinding {
                            status: "forwarded".into(),
                            target: Some(fwd.clone()),
                            forwarder: Some(fwd.clone()),
                            reason,
                            ..base
                        });
                    } else {
                        let address = match (snap.image_base, e.rva) {
                            (Some(b), Some(r)) => Some(b + r),
                            _ => None,
                        };
                        out.push(ImportBinding {
                            status: "bound".into(),
                            target: Some(format!(
                                "{}!{}",
                                snap.dll,
                                e.name.clone().unwrap_or_else(|| format!("#{}", e.ordinal.unwrap_or(0)))
                            )),
                            address,
                            ..base
                        });
                    }
                }
            }
        }
    }
    out
}
