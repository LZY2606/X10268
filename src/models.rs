use serde::{Deserialize, Serialize};

pub const RULE_VERSION: &str = "pe-loader-rules-2026.09";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Coordinate {
    pub value: String,
    pub unit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interval {
    pub start: u64,
    pub end: u64,
    pub unit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Material {
    pub material_id: String,
    pub kind: String,
    pub name: String,
    pub raw_base64: String,
    pub sha256: String,
    pub source_order: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByteSpan {
    pub span_id: String,
    pub material_id: String,
    pub name: String,
    pub start: u64,
    pub end: u64,
    pub unit: String,
    pub raw_base64: String,
    pub available: bool,
    pub diagnostic: Option<String>,
    pub source_order: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderField {
    pub header_field_id: String,
    pub span_id: String,
    pub name: String,
    pub offset: u64,
    pub width_bits: u32,
    pub original_hex: String,
    pub interpreted: serde_json::Value,
    pub unit: Option<String>,
    pub source_order: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionRow {
    pub section_id: String,
    pub name: String,
    pub raw: Interval,
    pub virtual_range: Interval,
    pub virtual_size_field: u64,
    pub raw_size_field: u64,
    pub characteristics: String,
    pub source_span_id: String,
    pub source_order: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataDirectoryRow {
    pub directory_id: String,
    pub name: String,
    pub index: usize,
    pub rva: u64,
    pub size: u64,
    pub coordinate_space: String,
    pub source_span_id: String,
    pub source_order: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelocationBlockRow {
    pub block_id: String,
    pub page_rva: u64,
    pub size: u64,
    pub source_span_id: String,
    pub source_order: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportDescriptorRow {
    pub descriptor_id: String,
    pub dll_name: String,
    pub original_first_thunk_rva: u64,
    pub first_thunk_rva: u64,
    pub name_rva: u64,
    pub source_span_id: String,
    pub source_order: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportThunkRow {
    pub thunk_id: String,
    pub descriptor_id: String,
    pub index: usize,
    pub ilt_rva: u64,
    pub iat_rva: u64,
    pub is_ordinal: bool,
    pub ordinal: Option<u16>,
    pub hint_name_rva: Option<u64>,
    pub name: Option<String>,
    pub original_qword_hex: String,
    pub source_span_id: String,
    pub source_order: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderRow {
    pub provider_id: String,
    pub material_id: String,
    pub dll_name: String,
    pub expected_image_base: String,
    pub present: bool,
    pub source_order: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportRow {
    pub export_id: String,
    pub provider_id: String,
    pub ordinal: u32,
    pub name: Option<String>,
    pub rva: String,
    pub forwarder: Option<String>,
    pub source_span_id: String,
    pub source_order: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Branch {
    pub branch_id: String,
    pub name: String,
    pub parent_branch_id: Option<String>,
    pub forked_from_event_id: Option<String>,
    pub created_order: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRecord {
    pub event_id: String,
    pub branch_id: String,
    pub seq: i64,
    pub kind: String,
    pub payload: serde_json::Value,
    pub parent_event_id: Option<String>,
    pub conflict_group: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseInput {
    pub case_id: String,
    pub title: String,
    pub expected_image_base: String,
    pub materials: Vec<Material>,
    pub spans: Vec<ByteSpan>,
    pub header_fields: Vec<HeaderField>,
    pub sections: Vec<SectionRow>,
    pub directories: Vec<DataDirectoryRow>,
    pub relocation_blocks: Vec<RelocationBlockRow>,
    pub import_descriptors: Vec<ImportDescriptorRow>,
    pub import_thunks: Vec<ImportThunkRow>,
    pub providers: Vec<ProviderRow>,
    pub exports: Vec<ExportRow>,
    pub branches: Vec<Branch>,
    pub events: Vec<EventRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Candidate {
    pub candidate_id: String,
    pub node_id: String,
    pub branch_id: String,
    pub label: String,
    pub value: serde_json::Value,
    pub source_span_ids: Vec<String>,
    pub status: String,
    pub rationale_event_id: String,
    pub ordinal: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeView {
    pub node_id: String,
    pub kind: String,
    pub label: String,
    pub coordinate: Option<String>,
    pub value: serde_json::Value,
    pub unit: Option<String>,
    pub status: String,
    pub rule_id: String,
    pub rule_version: String,
    pub derivation_event_id: String,
    pub source_span_ids: Vec<String>,
    pub source_material_ids: Vec<String>,
    pub dependencies: Vec<String>,
    pub invalidated_by: Vec<String>,
    pub candidates: Vec<Candidate>,
    pub decision_event_id: Option<String>,
    pub history: Vec<NodeHistory>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeHistory {
    pub event_id: String,
    pub seq: i64,
    pub kind: String,
    pub value_before: Option<serde_json::Value>,
    pub value_after: Option<serde_json::Value>,
    pub invalidation_scope: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgmentEvent {
    pub judgment_event_id: String,
    pub rule_id: String,
    pub rule_version: String,
    pub applies_to: Vec<String>,
    pub decision: String,
    pub rationale: String,
    pub evidence: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Projection {
    pub case_id: String,
    pub title: String,
    pub branch_id: String,
    pub head_event_id: Option<String>,
    pub branch_seq: i64,
    pub expected_image_base: String,
    pub actual_image_base: String,
    pub rule_version: String,
    pub sections: Vec<SectionRow>,
    pub directories: Vec<DataDirectoryRow>,
    pub spans: Vec<ByteSpan>,
    pub header_fields: Vec<HeaderField>,
    pub relocation_blocks: Vec<RelocationBlockRow>,
    pub import_descriptors: Vec<ImportDescriptorRow>,
    pub import_thunks: Vec<ImportThunkRow>,
    pub providers: Vec<ProviderRow>,
    pub exports: Vec<ExportRow>,
    pub nodes: Vec<NodeView>,
    pub visible_events: Vec<EventRecord>,
    pub judgments: Vec<JudgmentEvent>,
    pub branches: Vec<Branch>,
}

#[derive(Debug, Deserialize)]
pub struct EventPost {
    pub branch_id: String,
    pub expected_revision: i64,
    pub kind: String,
    pub node_id: Option<String>,
    pub candidate_id: Option<String>,
    pub actual_image_base: Option<String>,
    pub conflict_group: Option<String>,
    pub note: Option<String>,
}
