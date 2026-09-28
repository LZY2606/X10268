//! Loader-semantics derivation layer.
//!
//! Rules (versioned):
//!  * RVA -> file offset is multi-valued: a probe can be `mapped`,
//!    `zero_fill` (inside virtual size but beyond raw size), `unmapped`,
//!    or have several `overlap` candidates. All candidates are emitted;
//!    nothing is chosen at derive time.
//!  * Relocations are applied per type and bit width; values that do not
//!    fit the field width produce an `overflow` outcome, not truncation.
//!  * A missing DLL only produces `unresolved_import` facts; it never
//!    aborts binding of the remaining imports.

use crate::pe::{PeImage, SectionHeader};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const RULE_V1: &str = "loader-rules/1";
/// v2 changes one rule: zero-fill relocation targets are patched in the
/// virtual image instead of being flagged. Used to prove that a rule
/// change invalidates only dependent conclusions.
pub const RULE_V2: &str = "loader-rules/2";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MappingKind {
    Mapped,
    ZeroFill,
    Unmapped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingCandidate {
    pub rva: u32,
    pub kind: MappingKind,
    pub section: Option<String>,
    pub file_offset: Option<u32>,
}

/// All legal mappings for one RVA. Overlapping sections yield several
/// `Mapped`/`ZeroFill` candidates; the caller keeps them all.
pub fn rva_mapping_candidates(sections: &[SectionHeader], size_of_headers: u32, rva: u32) -> Vec<MappingCandidate> {
    let mut out = Vec::new();
    if rva < size_of_headers {
        out.push(MappingCandidate {
            rva,
            kind: MappingKind::Mapped,
            section: Some("<headers>".into()),
            file_offset: Some(rva),
        });
    }
    for s in sections {
        let span = s.virtual_size.max(s.raw_size);
        if rva >= s.virtual_address && rva < s.virtual_address + span {
            let within = rva - s.virtual_address;
            if within < s.raw_size {
                out.push(MappingCandidate {
                    rva,
                    kind: MappingKind::Mapped,
                    section: Some(s.name.clone()),
                    file_offset: Some(s.raw_ptr + within),
                });
            } else {
                out.push(MappingCandidate {
                    rva,
                    kind: MappingKind::ZeroFill,
                    section: Some(s.name.clone()),
                    file_offset: None,
                });
            }
        }
    }
    if out.is_empty() {
        out.push(MappingCandidate { rva, kind: MappingKind::Unmapped, section: None, file_offset: None });
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PatchStatus {
    Applied,
    Overflow,
    ZeroFillTarget,
    SkippedAbsolute,
    UnsupportedType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelocPatch {
    pub rva: u32,
    pub reloc_type: u8,
    pub type_name: String,
    pub width_bits: u32,
    pub old_value: u64,
    pub new_value: Option<u64>,
    pub status: PatchStatus,
}

pub fn reloc_width(reloc_type: u8) -> Option<u32> {
    match reloc_type {
        0 => Some(0),          // ABSOLUTE: skip
        1 | 2 => Some(16),     // HIGH / LOW
        3 => Some(32),         // HIGHLOW
        10 => Some(64),        // DIR64
        _ => None,
    }
}

/// Apply one relocation to `old_value` given `delta = load_base - preferred_base`.
/// Overflow is reported, never silently truncated.
pub fn apply_relocation(reloc_type: u8, old_value: u64, delta: i64) -> (Option<u64>, PatchStatus) {
    let Some(width) = reloc_width(reloc_type) else {
        return (None, PatchStatus::UnsupportedType);
    };
    if width == 0 {
        return (None, PatchStatus::SkippedAbsolute);
    }
    let mask: u128 = if width == 64 { u128::from(u64::MAX) } else { (1u128 << width) - 1 };
    let adjusted: i128 = match reloc_type {
        1 => (old_value as i128) + ((delta as i128) >> 16), // HIGH: high 16 bits
        _ => (old_value as i128) + (delta as i128),
    };
    if adjusted < 0 || adjusted as u128 > mask {
        return (None, PatchStatus::Overflow);
    }
    (Some(adjusted as u64), PatchStatus::Applied)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DllExportSnapshot {
    pub dll: String,
    /// name -> export record
    pub exports: Vec<ExportRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportRecord {
    pub name: Option<String>,
    pub ordinal: u16,
    /// RVA in the exporting image, or a forwarder string "DLL.Name".
    pub target: ExportTarget,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ExportTarget {
    Rva(u32),
    Forwarder(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BindingOutcome {
    Bound,
    ForwardedUnresolved, // forwarder target DLL snapshot missing
    Unresolved,          // dll missing or symbol absent
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportBinding {
    pub dll: String,
    pub import_name: String, // "ordinal:100" or the symbol name
    pub iat_rva: u32,
    pub outcome: BindingOutcome,
    pub resolved_to: Option<String>, // "KERNEL32.dll!ExitProcess" or forwarder chain text
    pub forwarder_chain: Vec<String>,
}

pub fn bind_import(
    dll: &str,
    import_name: &str,
    by_ordinal: bool,
    ordinal: Option<u16>,
    iat_rva: u32,
    snapshots: &[DllExportSnapshot],
) -> ImportBinding {
    let mut chain = Vec::new();
    let mut cur_dll = dll.to_string();
    let mut cur_name = import_name.to_string();
    let mut cur_ord = ordinal;
    let mut cur_by_ord = by_ordinal;
    for _hop in 0..8 {
        let Some(snap) = snapshots.iter().find(|s| s.dll.eq_ignore_ascii_case(&cur_dll)) else {
            return ImportBinding {
                dll: dll.into(),
                import_name: import_name.into(),
                iat_rva,
                outcome: if chain.is_empty() { BindingOutcome::Unresolved } else { BindingOutcome::ForwardedUnresolved },
                resolved_to: None,
                forwarder_chain: chain,
            };
        };
        let rec = if cur_by_ord {
            snap.exports.iter().find(|e| e.ordinal == cur_ord.unwrap_or(0))
        } else {
            snap.exports.iter().find(|e| e.name.as_deref() == Some(cur_name.as_str()))
        };
        let Some(rec) = rec else {
            return ImportBinding {
                dll: dll.into(),
                import_name: import_name.into(),
                iat_rva,
                outcome: if chain.is_empty() { BindingOutcome::Unresolved } else { BindingOutcome::ForwardedUnresolved },
                resolved_to: None,
                forwarder_chain: chain,
            };
        };
        match &rec.target {
            ExportTarget::Rva(rva) => {
                let label = rec.name.clone().unwrap_or_else(|| format!("#{}", rec.ordinal));
                return ImportBinding {
                    dll: dll.into(),
                    import_name: import_name.into(),
                    iat_rva,
                    outcome: BindingOutcome::Bound,
                    resolved_to: Some(format!("{}!{} @rva:0x{:x}", snap.dll, label, rva)),
                    forwarder_chain: chain,
                };
            }
            ExportTarget::Forwarder(fwd) => {
                chain.push(format!("{}!{}", snap.dll, rec.name.clone().unwrap_or_else(|| format!("#{}", rec.ordinal))));
                let mut parts = fwd.splitn(2, '.');
                cur_dll = parts.next().unwrap_or("").to_string();
                let tail = parts.next().unwrap_or("").to_string();
                if let Some(ord) = tail.strip_prefix('#').and_then(|s| s.parse::<u16>().ok()) {
                    cur_by_ord = true;
                    cur_ord = Some(ord);
                    cur_name = tail.clone();
                } else {
                    cur_by_ord = false;
                    cur_ord = None;
                    cur_name = tail;
                }
            }
        }
    }
    ImportBinding {
        dll: dll.into(),
        import_name: import_name.into(),
        iat_rva,
        outcome: BindingOutcome::ForwardedUnresolved,
        resolved_to: None,
        forwarder_chain: chain,
    }
}

/// Derived fact envelope: every value carries unit / coordinate basis.
pub fn qty(value: u64, unit: &str, basis: &str) -> Value {
    json!({ "value": value, "unit": unit, "basis": basis, "display": format!("0x{value:x} {unit} ({basis})") })
}

/// Probe RVAs that the loader view always maps: reloc targets, IAT slots,
/// directory starts, plus fixed edge probes.
pub fn probe_rvas(image: &PeImage) -> Vec<u32> {
    let mut v: Vec<u32> = Vec::new();
    for b in &image.reloc_blocks {
        for e in &b.entries {
            v.push(e.rva);
        }
    }
    for t in &image.imports {
        v.push(t.iat_rva);
    }
    for d in &image.directories {
        if d.rva != 0 {
            v.push(d.rva);
        }
    }
    // fixed edge probes: mapped / zero-fill / overlap / unmapped
    v.extend_from_slice(&[0x1100, 0x1300, 0x1500, 0x9000]);
    v.sort();
    v.dedup();
    v
}
