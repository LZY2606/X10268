//! Loader semantics. Every result keeps all legal candidates; nothing is
//! silently coerced to a single answer.

use crate::pe::{PeImage, Section, ThunkKind};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind")]
pub enum MapCandidate {
    /// RVA has raw file backing in this section.
    FileOffset { section: String, file_offset: u32 },
    /// RVA is inside virtual_size but beyond raw data: zero-filled at load.
    ZeroFill { section: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum MapResult {
    /// No section covers the RVA at all.
    Unmapped,
    /// One or more legal candidates (overlapping sections yield several).
    Candidates { candidates: Vec<MapCandidate> },
}

pub fn map_rva(sections: &[Section], rva: u32) -> MapResult {
    let mut out = Vec::new();
    for s in sections {
        let span = s.virtual_size.max(s.raw_size);
        if rva >= s.virtual_address && rva < s.virtual_address + span {
            let delta = rva - s.virtual_address;
            if delta < s.raw_size {
                out.push(MapCandidate::FileOffset {
                    section: s.name.clone(),
                    file_offset: s.raw_ptr + delta,
                });
            } else if delta < s.virtual_size {
                out.push(MapCandidate::ZeroFill { section: s.name.clone() });
            }
        }
    }
    if out.is_empty() {
        MapResult::Unmapped
    } else {
        MapResult::Candidates { candidates: out }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum RelocPatch {
    Applied {
        rva: u32,
        reloc_type: String,
        width_bits: u8,
        old_value: u64,
        new_value: u64,
        file_offset: u32,
    },
    /// value + delta does not fit the relocation width.
    Overflow {
        rva: u32,
        reloc_type: String,
        width_bits: u8,
        old_value: u64,
        delta: i64,
    },
    /// Relocation target RVA has no file backing (zero-fill or unmapped).
    NoFileBacking { rva: u32, reloc_type: String },
    Skipped { rva: u32, reloc_type: String },
    Unsupported { rva: u32, raw_type: u8 },
}

/// Apply base relocations for a move from `old_base` to `new_base`.
/// Width is dictated by the relocation type; overflow is reported, never
/// truncated silently.
pub fn apply_relocations(img: &PeImage, bytes: &[u8], new_base: u64) -> Vec<RelocPatch> {
    let delta = new_base as i128 - img.image_base as i128;
    let mut patches = Vec::new();
    for block in &img.reloc_blocks {
        for e in &block.entries {
            let rva = block.page_rva + e.offset_in_page as u32;
            let (width, bits) = match e.raw_type {
                0 => {
                    patches.push(RelocPatch::Skipped { rva, reloc_type: e.type_name.clone() });
                    continue;
                }
                3 => (4usize, 32u8),
                10 => (8usize, 64u8),
                other => {
                    patches.push(RelocPatch::Unsupported { rva, raw_type: other });
                    continue;
                }
            };
            let file_offset = match map_rva(&img.sections, rva) {
                MapResult::Candidates { candidates } => candidates.iter().find_map(|c| match c {
                    MapCandidate::FileOffset { file_offset, .. } => Some(*file_offset),
                    _ => None,
                }),
                MapResult::Unmapped => None,
            };
            let Some(fo) = file_offset else {
                patches.push(RelocPatch::NoFileBacking { rva, reloc_type: e.type_name.clone() });
                continue;
            };
            let o = fo as usize;
            if o + width > bytes.len() {
                patches.push(RelocPatch::NoFileBacking { rva, reloc_type: e.type_name.clone() });
                continue;
            }
            let old: u64 = if width == 4 {
                u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap()) as u64
            } else {
                u64::from_le_bytes(bytes[o..o + 8].try_into().unwrap())
            };
            let new = old as i128 + delta;
            let fits = if width == 4 { (0..=u32::MAX as i128).contains(&new) } else { (0..=u64::MAX as i128).contains(&new) };
            if !fits {
                patches.push(RelocPatch::Overflow {
                    rva,
                    reloc_type: e.type_name.clone(),
                    width_bits: bits,
                    old_value: old,
                    delta: i64::try_from(delta).unwrap_or(i64::MAX),
                });
            } else {
                patches.push(RelocPatch::Applied {
                    rva,
                    reloc_type: e.type_name.clone(),
                    width_bits: bits,
                    old_value: old,
                    new_value: new as u64,
                    file_offset: fo,
                });
            }
        }
    }
    patches
}

/// Snapshot of a DLL's exports, supplied as reference material.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExportEntry {
    pub name: Option<String>,
    pub ordinal: u16,
    /// Present when the export is forwarded, e.g. "real.dll!Func".
    pub forwarder: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DllSnapshot {
    pub dll: String,
    pub exports: Vec<ExportEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum Binding {
    Resolved {
        dll: String,
        import: String,
        target_dll: String,
        target: String,
        forwarded: bool,
        iat_rva: u32,
    },
    Unresolved {
        dll: String,
        import: String,
        reason: String,
    },
}

/// Bind imports against DLL export snapshots. A missing DLL only yields
/// unresolved imports for its thunks; everything else still binds.
pub fn bind_imports(img: &PeImage, snapshots: &[DllSnapshot]) -> Vec<Binding> {
    let find = |dll: &str| snapshots.iter().find(|s| s.dll.eq_ignore_ascii_case(dll));
    let mut out = Vec::new();
    for desc in &img.imports {
        let snap = find(&desc.dll_name);
        for th in &desc.thunks {
            let import_label = match &th.kind {
                ThunkKind::Ordinal { ordinal } => format!("#{ordinal}"),
                ThunkKind::Name { name, .. } => name.clone(),
            };
            let Some(snap) = snap else {
                out.push(Binding::Unresolved {
                    dll: desc.dll_name.clone(),
                    import: import_label,
                    reason: "missing-dll".into(),
                });
                continue;
            };
            let entry = match &th.kind {
                ThunkKind::Ordinal { ordinal } => snap.exports.iter().find(|e| e.ordinal == *ordinal),
                ThunkKind::Name { name, .. } => {
                    snap.exports.iter().find(|e| e.name.as_deref() == Some(name.as_str()))
                }
            };
            let Some(entry) = entry else {
                out.push(Binding::Unresolved {
                    dll: desc.dll_name.clone(),
                    import: import_label,
                    reason: "export-not-found".into(),
                });
                continue;
            };
            if let Some(fwd) = &entry.forwarder {
                // Forwarder form: "other.dll!Name" or "other.dll!#123".
                let (fdll, fname) = fwd.split_once('!').unwrap_or((fwd.as_str(), ""));
                let target_label = fname.to_string();
                let resolved = find(fdll).and_then(|s| {
                    if let Some(ord) = fname.strip_prefix('#').and_then(|n| n.parse::<u16>().ok()) {
                        s.exports.iter().find(|e| e.ordinal == ord)
                    } else {
                        s.exports.iter().find(|e| e.name.as_deref() == Some(fname))
                    }
                });
                match resolved {
                    Some(_) => out.push(Binding::Resolved {
                        dll: desc.dll_name.clone(),
                        import: import_label,
                        target_dll: fdll.to_string(),
                        target: target_label,
                        forwarded: true,
                        iat_rva: th.iat_rva,
                    }),
                    None => out.push(Binding::Unresolved {
                        dll: desc.dll_name.clone(),
                        import: import_label,
                        reason: format!("forwarder-target-missing:{fwd}"),
                    }),
                }
            } else {
                out.push(Binding::Resolved {
                    dll: desc.dll_name.clone(),
                    import: import_label,
                    target_dll: snap.dll.clone(),
                    target: entry.name.clone().unwrap_or_else(|| format!("#{}", entry.ordinal)),
                    forwarded: false,
                    iat_rva: th.iat_rva,
                });
            }
        }
    }
    out
}
