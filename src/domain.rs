use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const RULE_VERSION: &str = "pe-loader-rules/2026.1";
pub const CASE_ID: &str = "case-pe-loader-mirror-v1";
pub const PE_MATERIAL: &str = "sample-pe-bytes";
pub const SNAPSHOT_MATERIAL: &str = "dll-export-snapshot";
pub const EXPECTED_BASE: u64 = 0x1400_0000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Scalar {
    pub raw: String,
    pub value: u64,
    pub unit: String,
    pub basis: String,
}

impl Scalar {
    pub fn new(raw: impl Into<String>, value: u64, unit: &str, basis: &str) -> Self {
        Self { raw: raw.into(), value, unit: unit.to_string(), basis: basis.to_string() }
    }

    pub fn bytes(value: u64, basis: &str) -> Self {
        Self::new(format!("{value:#x}"), value, "byte", basis)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ByteSpan {
    pub blob_id: String,
    pub start: usize,
    pub end: usize,
    pub hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceRecord {
    pub id: String,
    pub material_id: String,
    pub version: u32,
    pub kind: String,
    pub path: String,
    pub label: String,
    pub raw_representation: String,
    pub span: Option<ByteSpan>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceRef {
    pub source_id: String,
    pub material_id: String,
    pub version: u32,
    pub byte_start: Option<usize>,
    pub byte_end: Option<usize>,
}

impl SourceRef {
    pub fn record(record: &SourceRecord) -> Self {
        Self {
            source_id: record.id.clone(),
            material_id: record.material_id.clone(),
            version: record.version,
            byte_start: record.span.as_ref().map(|s| s.start),
            byte_end: record.span.as_ref().map(|s| s.end),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Diagnostic {
    pub id: String,
    pub severity: String,
    pub code: String,
    pub message: String,
    pub sources: Vec<SourceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeaderField {
    pub id: String,
    pub label: String,
    pub raw: String,
    pub value: String,
    pub unit_or_basis: String,
    pub sources: Vec<SourceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Section {
    pub id: String,
    pub name: String,
    pub raw_start: Option<u64>,
    pub raw_end: Option<u64>,
    pub raw_size: u64,
    pub virtual_address: u64,
    pub virtual_end: u64,
    pub virtual_size: u64,
    pub status: Vec<String>,
    pub sources: Vec<SourceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataDirectoryRecord {
    pub id: String,
    pub index: u8,
    pub name: String,
    pub rva: u64,
    pub size: u64,
    pub raw_rva: String,
    pub raw_size: String,
    pub status: String,
    pub diagnostic: Option<String>,
    pub sources: Vec<SourceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MappingCandidate {
    pub id: String,
    pub section_id: Option<String>,
    pub kind: String,
    pub file_offset: Option<u64>,
    pub byte_supply: String,
    pub status: String,
    pub sources: Vec<SourceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AddressProbe {
    pub id: String,
    pub rva: u64,
    pub va: u64,
    pub candidates: Vec<MappingCandidate>,
    pub resolution: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelocationPatch {
    pub id: String,
    pub block_id: String,
    pub type_name: String,
    pub type_code: u8,
    pub width_bits: u8,
    pub location_rva: u64,
    pub location_va: u64,
    pub old_hex: String,
    pub new_hex: String,
    pub status: String,
    pub diagnostic: Option<String>,
    pub sources: Vec<SourceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportBinding {
    pub id: String,
    pub dll_id: String,
    pub dll: String,
    pub ordinal: Option<u64>,
    pub name: Option<String>,
    pub iat_rva: u64,
    pub status: String,
    pub resolved_symbol: Option<String>,
    pub resolved_va: Option<u64>,
    pub forward_chain: Vec<String>,
    pub diagnostic: Option<String>,
    pub sources: Vec<SourceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Notice {
    pub id: String,
    pub kind: String,
    pub message: String,
    pub affected_ids: Vec<String>,
    pub changed_sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Analysis {
    pub rule_version: String,
    pub expected_base: u64,
    pub actual_base: u64,
    pub pe_version: u32,
    pub snapshot_version: u32,
    pub size_of_image: u64,
    pub headers: Vec<HeaderField>,
    pub sections: Vec<Section>,
    pub directories: Vec<DataDirectoryRecord>,
    pub probes: Vec<AddressProbe>,
    pub relocations: Vec<RelocationPatch>,
    pub imports: Vec<ImportBinding>,
    pub diagnostics: Vec<Diagnostic>,
    pub notices: Vec<Notice>,
    pub source_records: Vec<SourceRecord>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DecisionAction {
    Accepted,
    Denied,
    Revoked,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventKind {
    Import,
    ParameterRevision,
    SourceRevision,
    Decision,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventRecord {
    pub event_id: String,
    pub branch_id: String,
    pub parent_event_id: Option<String>,
    pub depth: i64,
    pub seq: i64,
    pub kind: EventKind,
    pub rule_version: String,
    pub pe_version: u32,
    pub snapshot_version: u32,
    pub actual_base: u64,
    pub payload: serde_json::Value,
    pub created_order: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionState {
    pub candidate_id: String,
    pub action: DecisionAction,
    pub event_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportArchive {
    pub archive_schema: String,
    pub case_id: String,
    pub title: String,
    pub blobs: Vec<BlobExport>,
    pub material_versions: Vec<MaterialExport>,
    pub source_records: Vec<SourceRecord>,
    pub branches: Vec<BranchExport>,
    pub events: Vec<EventRecord>,
    pub snapshots: Vec<SnapshotExport>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlobExport {
    pub blob_id: String,
    pub content_base64: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MaterialExport {
    pub material_id: String,
    pub version: u32,
    pub kind: String,
    pub path: String,
    pub raw_text: String,
    pub blob_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BranchExport {
    pub branch_id: String,
    pub name: String,
    pub parent_branch_id: Option<String>,
    pub fork_event_id: Option<String>,
    pub head_event_id: String,
    pub version: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotExport {
    pub event_id: String,
    pub analysis_json: String,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn u16le(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

pub fn u32le(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

pub fn u64le(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
