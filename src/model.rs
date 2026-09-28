use serde::{Deserialize, Serialize};

pub const RULE_VERSION_1: &str = "rule-pe-loader-1.0.0";
pub const RULE_VERSION_2: &str = "rule-pe-loader-2.0.0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Material {
    pub material_id: String,
    pub kind: String,
    pub label: String,
    pub revision: u32,
    pub original_representation: serde_json::Value,
    pub bytes: String,
    pub byte_encoding: String,
    pub supersedes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceRef {
    pub material_id: String,
    pub revision: u32,
    pub offset: u64,
    pub length: u64,
    pub coordinate_basis: String,
    pub representation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Candidate {
    pub candidate_id: String,
    pub subject_id: String,
    pub subject_kind: String,
    pub subject_label: String,
    pub option_id: String,
    pub option_label: String,
    pub status: String,
    pub value: serde_json::Value,
    pub evidence: Vec<EvidenceRef>,
    pub source_refs: Vec<String>,
    pub invalidated_by: Option<String>,
    pub depends_on: Vec<String>,
    pub rule_version: String,
    pub params_revision: u32,
    pub material_revision: u32,
    pub batch: String,
    pub created_by_event: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventRecord {
    pub event_id: String,
    pub parent_event_id: Option<String>,
    pub sequence: i64,
    pub kind: String,
    pub label: String,
    pub rule_version: String,
    pub params_revision: u32,
    pub material_revision: u32,
    pub branch_id: String,
    pub payload: serde_json::Value,
    pub invalidation_scope: Vec<String>,
    pub actor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Branch {
    pub branch_id: String,
    pub label: String,
    pub head_event_id: String,
    pub created_from_event_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bundle {
    pub schema_version: u32,
    pub materials: Vec<Material>,
    pub events: Vec<EventRecord>,
    pub candidates: Vec<Candidate>,
    pub branches: Vec<Branch>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DecisionInput {
    pub parent_event_id: String,
    pub branch_id: String,
    pub subject_id: String,
    pub accepted_option_id: String,
    pub label: String,
    pub rationale: String,
    pub expected_parent_event_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ParameterInput {
    pub parent_event_id: String,
    pub branch_id: String,
    pub label: String,
    pub rationale: String,
    pub expected_image_base: u64,
    pub expected_parent_event_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SourceChangeInput {
    pub parent_event_id: String,
    pub branch_id: String,
    pub label: String,
    pub rationale: String,
    pub expected_parent_event_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConflictDetail {
    pub your_parent: String,
    pub current_head: String,
    pub your_summary: String,
    pub current_summary: String,
    pub differing_subjects: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConflictResponse {
    pub error: String,
    pub code: String,
    pub details: ConflictDetail,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiError {
    pub error: String,
    pub code: String,
}
