use rusqlite::types::Value as SqlValue;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

pub type AppError = Box<dyn std::error::Error + Send + Sync>>;
pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Q {
    pub value: u64,
    pub raw: String,
    pub unit: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basis: Option<String>,
}

impl Q {
    pub fn new(value: u64, unit: impl Into<String>, basis: Option<&str>) -> Self {
        Self {
            value,
            raw: format!("0x{value:X}"),
            unit: unit.into(),
            basis: basis.map(str::to_string),
        }
    }

    pub fn file_offset(value: u64) -> Self {
        Self::new(value, "byte/file-offset", Some("little-endian file byte coordinate"))
    }

    pub fn rva(value: u64) -> Self {
        Self::new(value, "byte/rva", Some("image base relative virtual address"))
    }

    pub fn va(value: u64) -> Self {
        Self::new(value, "byte/virtual-address", Some("absolute simulated virtual address"))
    }

    pub fn bytes(value: u64) -> Self {
        Self::new(value, "byte", Some("unsigned byte count"))
    }

    pub fn ordinal(value: u64) -> Self {
        Self::new(value, "ordinal", Some("PE ordinal/name 16-bit table"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceRef {
    pub material_id: String,
    pub material_version: String,
    pub file_offset: Q,
    pub length: Q,
    pub hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FieldValue {
    Text(String),
    Quantity(Q),
    Bytes { hex: String, length: Q },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Field {
    pub id: String,
    pub label: String,
    pub raw: String,
    pub value: FieldValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaterialVersion {
    pub case_id: String,
    pub material_id: String,
    pub version: String,
    pub role: String,
    pub name: String,
    pub content: JsonValue,
    pub introduced_event_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Branch {
    pub case_id: String,
    pub branch_id: String,
    pub name: String,
    pub base_event_id: Option<String>,
    pub parent_branch_id: Option<String>,
    pub head_event_id: Option<String>,
    pub head_seq: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRecord {
    pub case_id: String,
    pub event_id: String,
    pub branch_id: String,
    pub seq: i64,
    pub kind: String,
    pub title: String,
    pub summary: String,
    pub parameters: JsonValue,
    pub basis: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRevision {
    pub case_id: String,
    pub artifact_id: String,
    pub revision_event_id: String,
    pub kind: String,
    pub status: String,
    pub display_order: i64,
    pub value: JsonValue,
}

#[derive(Debug, Clone)]
pub struct NewArtifact {
    pub artifact_id: String,
    pub kind: String,
    pub status: String,
    pub display_order: i64,
    pub value: JsonValue,
    pub deps: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub case_id: String,
    pub branch_id: String,
    pub decision_id: String,
    pub event_id: String,
    pub subject_id: String,
    pub action: String,
    pub candidate_id: String,
    pub rationale: String,
    pub revoked_event_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseBundle {
    pub schema_version: u32,
    pub case: JsonValue,
    pub material_versions: Vec<JsonValue>,
    pub branches: Vec<JsonValue>,
    pub events: Vec<JsonValue>,
    pub event_parents: Vec<(String, String)>,
    pub artifact_revisions: Vec<JsonValue>,
    pub artifact_deps: Vec<(String, String, String, String, String, Option<String>)>,
    pub decisions: Vec<JsonValue>,
}

pub fn json_to_sql(value: &JsonValue) -> SqlValue {
    match value {
        JsonValue::Null => SqlValue::Null,
        JsonValue::Bool(v) => SqlValue::Integer(i64::from(*v)),
        JsonValue::Number(v) => {
            if let Some(i) = v.as_i64() {
                SqlValue::Integer(i)
            } else {
                SqlValue::Real(v.as_f64().unwrap_or(0.0))
            }
        }
        JsonValue::String(v) => SqlValue::Text(v.clone()),
        JsonValue::Array(_) | JsonValue::Object(_) => {
            SqlValue::Text(serde_json::to_string(value).expect("json value"))
        }
    }
}

pub fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

pub fn parse_hex(hex: &str) -> AppResult<Vec<u8>> {
    let clean: String = hex.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).map_err(Into::into))
        .collect()
}
