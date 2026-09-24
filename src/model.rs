//! 领域模型：原始材料（source）与解释（interpretation）严格分离。
//!
//! 所有字段都带显式坐标基准/单位：
//! - 文件偏移单位 byte（`unit: "byte"`）
//! - 虚拟地址使用 `rva`（相对 image base）或 `va`（base + rva）
//! - 位数使用 `bit`
//! 无法转换的值保留在 `raw_repr` 并在 `diagnostics` 中给出诊断，不做不可逆清洗。

use serde::{Deserialize, Serialize};

pub const BYTE: &str = "byte";
pub const RVA: &str = "rva";
pub const VA: &str = "va";

/// 带坐标基准的整数值。`raw_repr` 保留导入时的原始表示。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Coord {
    pub value: i64,
    pub unit: String,
    #[serde(default)]
    pub raw_repr: String,
}

impl Coord {
    pub fn byte(value: i64) -> Self {
        Coord { value, unit: BYTE.into(), raw_repr: format!("0x{value:X}") }
    }
    pub fn rva(value: i64) -> Self {
        Coord { value, unit: RVA.into(), raw_repr: format!("0x{value:X}") }
    }
}

/// 字节来源：任何派生值都可回溯到 artifact 的字节区间。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ByteSource {
    pub artifact_id: String,
    pub offset: i64,
    pub len: i64,
    /// 字段路径，例如 "dos_header.e_lfanew" / "section[1].virtual_address"。
    pub field: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Diagnostic {
    pub code: String,
    pub severity: String, // error | warning | info
    pub message: String,
    #[serde(default)]
    pub byte_source: Option<ByteSource>,
}

/// 原始材料（事实层，不做规范化推断）。`kind` 决定 `payload` 的具体结构。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Material {
    pub id: String,
    pub kind: String,
    pub ordinal: i64,
    pub payload: serde_json::Value,
    #[serde(default)]
    pub byte_sources: Vec<ByteSource>,
    #[serde(default)]
    pub diagnostics: Vec<Diagnostic>,
}

/// 规则/参数版本。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleSet {
    pub id: String,
    pub version: i64,
    /// 规则参数，例如 `{"zero_fill_beyond_raw": true, "reloc_delta_base": "preferred"}`。
    pub params: serde_json::Value,
    pub note: String,
}

/// 事件（追加日志，禁止原地修改）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Event {
    pub id: String,
    pub branch_id: String,
    pub seq: i64,
    pub kind: String, // import | material_update | rule_revise | decision | branch_create
    pub parent_event_id: Option<String>,
    pub timestamp: String,
    pub payload: serde_json::Value,
}

/// 候选裁定。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Decision {
    pub fact_id: String,
    pub candidate_id: String,
    pub action: String, // accept | reject
    pub rationale: String,
}

/// 失效报告：规则/参考版本变化后，按依赖边计算，而非全局替换。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Invalidation {
    pub changed_input: String,
    pub recomputed_fact_ids: Vec<String>,
    pub invalidated_decision_ids: Vec<String>,
    pub unaffected_fact_ids: Vec<String>,
}
