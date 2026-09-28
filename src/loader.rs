//! Loader semantics: section mapping, base relocations and import binding.
//!
//! Deliberate rules:
//! * RVA -> file offset can be *unmapped*, *ambiguous* (section overlap) or
//!   *zero-fill only* (virtual size beyond raw size). No candidate is silently
//!   picked; all legal candidates are kept for human adjudication.
//! * Relocations execute by type and field width; a value that does not fit the
//!   width is recorded as an overflow, never truncated.
//! * A missing DLL produces unresolved imports only; it is not a load error.

use serde::{Deserialize, Serialize};

use crate::pe::{self, ImportLookup, ParsedPe, RelocKind, SectionHeader};

/// A single legal explanation of where an RVA gets its bytes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MapCandidate {
    pub kind: String,
    pub section: Option<String>,
    pub file_offset: Option<u32>,
    pub basis: String,
}

/// All legal candidates for one RVA. `probed` RVA points come from sections /
/// relocations / IAT slots so every sampled address has an explicit verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RvaVerdict {
    pub rva: u32,
    pub candidates: Vec<MapCandidate>,
    pub state: String,
    pub origin: String,
}

pub fn rva_candidates(rva: u32, sections: &[SectionHeader], file_len: u32, origin: &str) -> RvaVerdict {
    let mut cands = Vec::new();
    for s in sections {
        if rva < s.vaddr || rva >= s.vaddr.saturating_add(s.vsize) {
            continue;
        }
        let delta = rva - s.vaddr;
        if delta < s.raw_size {
            if let Some(off) = s.raw_ptr.checked_add(delta) {
                if (off as usize) < file_len as usize {
                    cands.push(MapCandidate {
                        kind: "file_offset".into(),
                        section: Some(s.name.clone()),
                        file_offset: Some(off),
                        basis: "raw_ptr+(rva-vaddr)".into(),
                    });
                    continue;
                }
            }
        }
        cands.push(MapCandidate {
            kind: "zero_fill".into(),
            section: Some(s.name.clone()),
            file_offset: None,
            basis: "vsize>raw: loader zero-fills tail".into(),
        });
    }
    let state = if cands.is_empty() {
        "unmapped".into()
    } else if cands.len() > 1 {
        "overlap".into()
    } else {
        cands[0].kind.clone()
    };
    RvaVerdict {
        rva,
        candidates: cands,
        state,
        origin: origin.into(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelocResult {
    pub rva: u32,
    pub kind: String,
    pub width_bits: Option<u32>,
    pub preferred_base: u64,
    pub actual_base: u64,
    pub delta: i128,
    pub old_value: Option<u64>,
    pub patched_value: Option<u64>,
    pub status: String,
    pub source_span_off: u32,
}

/// Apply one relocation. `field_value` is read through the same RVA map; a
/// missing backing makes the patch `unmapped_field` instead of guessing zero.
pub fn apply_reloc(
    entry: &pe::RelocEntry,
    preferred_base: u64,
    actual_base: u64,
    field_value: Option<u64>,
) -> RelocResult {
    let width = entry.kind.width_bits();
    let delta = actual_base as i128 - preferred_base as i128;
    let mut status = "ok".to_string();
    let mut patched: Option<u64> = None;
    if field_value.is_none() {
        status = "unmapped_field".into();
    }
    match width {
        Some(w) if w > 0 => {
            if let Some(old) = field_value {
                let pv = old as i128 + delta;
                let max = if w == 64 { u64::MAX } else { (1u64 << w) - 1 };
                if pv < 0 || pv as u128 > max as u128 {
                    status = "overflow".into();
                } else {
                    patched = Some(pv as u64);
                }
            }
        }
        Some(_) => {}
        None => {
            if status == "ok" {
                status = "unsupported_type".into();
            }
        }
    }
    RelocResult {
        rva: entry.rva,
        kind: entry.kind.name(),
        width_bits: width,
        preferred_base,
        actual_base,
        delta,
        old_value: field_value,
        patched_value: patched,
        status,
        source_span_off: entry.span.off,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DllExport {
    pub name: Option<String>,
    pub ordinal: u16,
    pub forwarder: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DllSnapshot {
    pub dll: String,
    pub exports: Vec<DllExport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportResult {
    pub iat_rva: u32,
    pub dll: String,
    pub by: String,
    pub symbol: String,
    pub ordinal: Option<u16>,
    pub status: String,
    pub bound_to: Option<String>,
    pub forward_chain: Vec<String>,
    pub source_span_off: u32,
}

pub fn bind_import(t: &pe::ImportThunk, snapshots: &[DllSnapshot]) -> ImportResult {
    let (by, symbol, ordinal) = match &t.lookup {
        ImportLookup::Name { name, .. } => ("name", name.clone(), None),
        ImportLookup::Ordinal(o) => ("ordinal", format!("#{}", o), Some(*o)),
    };
    let snap = snapshots.iter().find(|s| s.dll.eq_ignore_ascii_case(&t.dll));
    let (status, bound, chain) = match snap {
        None => ("unresolved_dll".to_string(), None, vec![]),
        Some(s) => {
            let hit = s.exports.iter().find(|e| match &t.lookup {
                ImportLookup::Name { name, .. } => e.name.as_deref() == Some(name.as_str()),
                ImportLookup::Ordinal(o) => e.ordinal == *o,
            });
            match hit {
                None => ("unresolved_symbol".to_string(), None, vec![]),
                Some(exp) => {
                    if let Some(fwd) = &exp.forwarder {
                        let target = exp
                            .name
                            .clone()
                            .unwrap_or_else(|| ordinal.map(|o| format!("#{}", o)).unwrap_or_default());
                        (
                            "forwarded".to_string(),
                            Some(fwd.clone()),
                            vec![format!("{}!{}", s.dll, target), fwd.clone()],
                        )
                    } else {
                        ("resolved".to_string(), Some(exp.name.clone().unwrap_or_else(|| symbol.clone())), vec![])
                    }
                }
            }
        }
    };
    ImportResult {
        iat_rva: t.iat_rva,
        dll: t.dll.clone(),
        by: by.into(),
        symbol,
        ordinal,
        status,
        bound_to: bound,
        forward_chain: chain,
        source_span_off: t.lookup_span.off,
    }
}

/// Everything a single interpretation run derives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interpretation {
    pub rule_version: u32,
    pub preferred_base_raw: String,
    pub preferred_base: u64,
    pub actual_base: u64,
    pub sections: Vec<SectionHeader>,
    pub rva_verdicts: Vec<RvaVerdict>,
    pub relocs: Vec<RelocResult>,
    pub imports: Vec<ImportResult>,
    pub diagnostics: Vec<pe::Diagnostic>,
}

/// Read a width-aware little-endian field through the candidate map.
fn read_field(verdict: &RvaVerdict, bytes: &[u8], width_bits: u32) -> Option<u64> {
    let cand = verdict.candidates.iter().find(|c| c.kind == "file_offset")?;
    let off = cand.file_offset? as usize;
    let n = (width_bits / 8) as usize;
    if off + n > bytes.len() {
        return None;
    }
    let mut v = 0u64;
    for i in 0..n {
        v |= (bytes[off + i] as u64) << (8 * i);
    }
    Some(v)
}

pub fn interpret(
    parsed: &ParsedPe,
    bytes: &[u8],
    snapshots: &[DllSnapshot],
    actual_base: u64,
    actual_base_raw: &str,
    rule_version: u32,
) -> Interpretation {
    let nt = parsed.nt.as_ref().expect("interpreted only with NT headers");
    let sections = nt.sections.clone();
    let file_len = bytes.len() as u32;
    let mut verdicts = Vec::new();
    let mut probe = |rva: u32, origin: &str, seen: &mut Vec<u32>| {
        if !seen.contains(&rva) {
            seen.push(rva);
            verdicts.push(rva_candidates(rva, &sections, file_len, origin));
        }
    };
    let mut seen = Vec::new();
    for s in &sections {
        probe(s.vaddr, &format!("section:{}:start", s.name), &mut seen);
        if s.vsize > s.raw_size {
            probe(s.vaddr + s.raw_size, &format!("section:{}:zerofill", s.name), &mut seen);
        }
        let mut other: Option<&SectionHeader> = None;
        for o in &sections {
            if o.name != s.name
                && s.vaddr < o.vaddr + o.vsize
                && o.vaddr < s.vaddr + s.vsize
            {
                other = Some(o);
            }
        }
        if let Some(o) = other {
            let lo = s.vaddr.max(o.vaddr);
            probe(lo, &format!("overlap:{}|{}", s.name, o.name), &mut seen);
        }
    }
    let mut relocs = Vec::new();
    for e in &parsed.relocs {
        let v = rva_candidates(e.rva, &sections, file_len, "reloc:field");
        let width = e.kind.width_bits().unwrap_or(0);
        let fv = if width > 0 { read_field(&v, bytes, width) } else { None };
        if !seen.contains(&e.rva) {
            seen.push(e.rva);
            verdicts.push(v.clone());
        }
        relocs.push(apply_reloc(e, nt.image_base, actual_base, fv));
    }
    for t in &parsed.imports {
        probe(t.iat_rva, &format!("iat:{}", t.dll), &mut seen);
    }
    verdicts.sort_by_key(|v| v.rva);
    let imports = parsed.imports.iter().map(|t| bind_import(t, snapshots)).collect();
    Interpretation {
        rule_version,
        preferred_base_raw: nt.image_base_raw.clone(),
        preferred_base: nt.image_base,
        actual_base,
        sections,
        rva_verdicts: verdicts,
        relocs,
        imports,
        diagnostics: parsed.diagnostics.clone(),
    }
}
