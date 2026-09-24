//! RVA -> source resolution.
//!
//! Core rule (ruleset `pe-loader-rules/1`): an RVA may be *unmapped*, backed by
//! *overlapping* sections, or backed only by *zero-fill* (virtual tail beyond
//! raw size). The resolver never silently picks one; it returns every legal
//! candidate and lets the interpretation layer / reviewer arbitrate.

use crate::core::Section;
use serde::{Deserialize, Serialize};

/// Where bytes for an RVA range physically come from.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Origin {
    pub section_index: u32,
    pub section_name: String,
    /// File offset when raw-backed; `None` for a virtual-only zero-fill range.
    pub file_offset: Option<u64>,
    pub kind: OriginKind,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum OriginKind {
    /// Bytes exist in the file at `file_offset`.
    #[serde(rename = "raw")]
    Raw,
    /// Mapped virtual range beyond the raw data: the loader supplies zero
    /// bytes; there is intentionally no file offset.
    #[serde(rename = "zero-fill")]
    ZeroFill,
    /// Requested range straddles the raw/zero-fill boundary: only part of it is
    /// raw-backed. Kept as a distinct, non-forced candidate.
    #[serde(rename = "partial-raw")]
    PartialRaw,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolutionKind {
    #[serde(rename = "unique")]
    Unique,
    #[serde(rename = "overlapping")]
    Overlapping,
    #[serde(rename = "zero-fill-only")]
    ZeroFillOnly,
    #[serde(rename = "unmapped")]
    Unmapped,
}

pub struct Resolution {
    pub kind: ResolutionKind,
    pub origins: Vec<Origin>,
}

/// Resolve every legal source for `[rva, rva+len)`.
pub fn resolve_range(sections: &[Section], rva: u64, len: u64) -> Resolution {
    let mut origins = Vec::new();
    for s in sections {
        let va = s.virtual_address;
        let vs = s.virtual_size.max(s.raw_size);
        if rva + len <= va || rva >= va + vs {
            continue;
        }
        let in_off = rva.saturating_sub(va);
        let raw = s.raw_size;
        let file_off;
        let kind;
        if in_off + len <= raw {
            file_off = Some(s.raw_offset + in_off);
            kind = OriginKind::Raw;
        } else if in_off >= raw {
            file_off = None;
            kind = OriginKind::ZeroFill;
        } else {
            file_off = Some(s.raw_offset + in_off);
            kind = OriginKind::PartialRaw;
        }
        origins.push(Origin {
            section_index: s.index,
            section_name: s.name.clone(),
            file_offset: file_off,
            kind,
        });
    }
    let kind = classify(&origins);
    Resolution { kind, origins }
}

fn classify(origins: &[Origin]) -> ResolutionKind {
    if origins.is_empty() {
        ResolutionKind::Unmapped
    } else if origins.len() > 1 {
        ResolutionKind::Overlapping
    } else if origins[0].kind == OriginKind::ZeroFill {
        ResolutionKind::ZeroFillOnly
    } else {
        ResolutionKind::Unique
    }
}

/// Read up to `len` bytes for an origin from the material. Zero-fill origins
/// always read as zeros; partial-raw reads zero-pad beyond the raw part.
pub fn read_bytes(pe: &[u8], sections: &[Section], o: &Origin, len: usize) -> Vec<u8> {
    match o.kind {
        OriginKind::ZeroFill => vec![0u8; len],
        OriginKind::Raw => {
            let start = o.file_offset.unwrap() as usize;
            pe.get(start..start + len).unwrap_or_default().to_vec()
        }
        OriginKind::PartialRaw => {
            let s = &sections[o.section_index as usize];
            let avail = s.raw_size.saturating_sub(o.file_offset.unwrap() - s.raw_offset);
            let start = o.file_offset.unwrap() as usize;
            let mut out = pe.get(start..start + avail as usize).unwrap_or_default().to_vec();
            out.resize(len, 0);
            out
        }
    }
}

/// Read a NUL-terminated ASCII string for each origin (up to the section's
/// virtual end), returning (string, origin) pairs.
pub fn read_cstr_variants(
    pe: &[u8],
    sections: &[Section],
    rva: u64,
) -> Vec<(Origin, String)> {
    let mut out = Vec::new();
    for s in sections {
        let va = s.virtual_address;
        let vs = s.virtual_size.max(s.raw_size);
        if rva < va || rva >= va + vs {
            continue;
        }
        let in_off = rva - va;
        let cap = (vs - in_off) as usize;
        let o = if in_off >= s.raw_size {
            Origin {
                section_index: s.index,
                section_name: s.name.clone(),
                file_offset: None,
                kind: OriginKind::ZeroFill,
            }
        } else {
            Origin {
                section_index: s.index,
                section_name: s.name.clone(),
                file_offset: Some(s.raw_offset + in_off),
                kind: OriginKind::Raw,
            }
        };
        let mut buf = Vec::new();
        match o.kind {
            OriginKind::ZeroFill => buf = vec![0u8; cap.min(256)],
            _ => {
                let start = o.file_offset.unwrap() as usize;
                let raw_avail = if in_off < s.raw_size {
                    (s.raw_size - in_off) as usize
                } else {
                    0
                };
                let n = cap.min(256).min(raw_avail);
                buf = pe.get(start..start + n).unwrap_or_default().to_vec();
            }
        }
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        let s2 = String::from_utf8_lossy(&buf[..end]).to_string();
        out.push((o, s2));
    }
    out
}
