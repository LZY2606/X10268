//! Stable, content-derived identifiers so identity survives export/import and
//! database deletion. IDs are hashes of the same canonical inputs everywhere.

use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// `prefix:` + first 16 hex chars of sha256 over the concatenation of parts.
pub fn stable_id(prefix: &str, parts: &[&str]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p.as_bytes());
    }
    format!("{}:{}", prefix, hex::encode(h.finalize())[..16].to_string())
}

pub fn pe_material_id(sha: &str) -> String {
    format!("mat-pe:{}", &sha[..16])
}

pub fn snap_material_id(sha: &str) -> String {
    format!("mat-snap:{}", &sha[..16])
}

pub fn dll_snapshot_id(pe_id: &str, dll_key: &str, sha: &str) -> String {
    stable_id("snap", &[pe_id, dll_key, &sha[..16]])
}

pub fn main_branch_id(case_id: &str) -> String {
    stable_id("branch-main", &[case_id])
}

pub fn probe_branch_id(case_id: &str) -> String {
    stable_id("branch-probe", &[case_id])
}

/// Event ids are deterministic over (case, branch, ordinal sequence, kind,
/// payload hash) so a replayed case produces identical history.
pub fn event_id(case_id: &str, branch_id: &str, seq: u32, kind: &str, payload_hash: &str) -> String {
    stable_id("ev", &[case_id, branch_id, &seq.to_string(), kind, payload_hash])
}

pub fn case_id_from_pe(sha: &str) -> String {
    format!("case:{}", &sha[..16])
}
