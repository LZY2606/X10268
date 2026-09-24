//! 领域类型：来源（source）与解释（interpretation）严格分离。
//!
//! 所有领域量都携带单位或坐标基准：导入时保留原始表示（raw），
//! 派生层才做规范化（normalized）；无法转换的值留在原位置并附诊断。

use serde::{Deserialize, Serialize};

/// 坐标基准 / 单位。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Basis {
    /// 文件字节偏移，单位 byte，原点为文件第 0 字节。
    FileByte,
    /// 相对虚拟地址，单位 byte，原点为 image base 之后。
    RvaByte,
    /// 虚拟地址，单位 byte，原点为镜像 image base。
    VaByte,
    /// 节原始数据尺寸，单位 byte（文件对齐网格）。
    RawSizeByte,
    /// 节虚拟内存尺寸，单位 byte（节对齐网格）。
    VirtualSizeByte,
    /// 无单位的标量（例如 ordinal、标志位、计数值）。
    Scalar,
}

impl Basis {
    pub fn as_str(self) -> &'static str {
        match self {
            Basis::FileByte => "byte@file[0]",
            Basis::RvaByte => "byte@rva[imagebase]",
            Basis::VaByte => "byte@va[0]",
            Basis::RawSizeByte => "byte(raw-size,file-align)",
            Basis::VirtualSizeByte => "byte(virtual-size,section-align)",
            Basis::Scalar => "scalar",
        }
    }
}

/// 一个“带原始表示”的领域量。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawValue {
    /// 规范化后的整数值（若可转换）。
    pub value: Option<i64>,
    /// 导入时的原始表示，例如 "0x1000"、"4096"、"<truncated>"。
    pub raw: String,
    /// 单位 / 坐标基准。
    pub basis: String,
    /// 转换诊断；None 表示原始表示可无损规范化。
    pub conversion: Option<Diagnostic>,
}

impl RawValue {
    pub fn new(value: i64, raw: impl Into<String>, basis: Basis) -> Self {
        RawValue { value: Some(value), raw: raw.into(), basis: basis.as_str().to_string(), conversion: None }
    }

    pub fn unconvertible(raw: impl Into<String>, basis: Basis, diag: Diagnostic) -> Self {
        RawValue { value: None, raw: raw.into(), basis: basis.as_str().to_string(), conversion: Some(diag) }
    }
}

/// 诊断：无法转换 / 越界 / 损坏等，停留在原位置，绝不为了画图而丢值。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub code: String,
    pub message: String,
}

impl Diagnostic {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Diagnostic { code: code.into(), message: message.into() }
    }
}

/// 稳定身份：所有展示值都带稳定身份；由坐标（而非易变行号）决定。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StableId(pub String);

impl StableId {
    pub fn as_str(&self) -> &str { &self.0 }
}

/// 字节来源区间：事实引用的原始字节都可回溯到 blob 中的 [start,end)。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteSpan {
    pub blob_id: String,
    pub start: u64,
    pub end: u64,
}

/// 导入批次：一次导入要么整体提交，要么整体回滚，不留半份记录。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngestionInput {
    pub expected_image_base: Option<u64>,
    pub pe_bytes_b64: String,
    /// 可选 DLL export 快照：dll 名（小写） -> 快照。
    pub dll_snapshots: Vec<DllSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DllSnapshot {
    pub dll_name: String,
    pub source_label: String,
    pub exports: Vec<DllExport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DllExport {
    pub name: Option<String>,
    /// ordinal 在快照中的原始表示。
    pub ordinal_raw: String,
    pub rva: Option<u32>,
    /// 转发目标，例如 "OTHERDLL.OtherFunc"。
    pub forwarder: Option<String>,
}

/// 事件类型（事件溯源）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventPayload {
    /// 初始导入（事实基线）。
    Ingestion {
        ingestion_id: String,
        expected_image_base_raw: String,
        blob_sha256: String,
        dll_labels: Vec<String>,
    },
    /// 参数修订：改 image base（会让按宽度执行的重定位溢出）。
    ParameterRevision {
        parameter: String,
        old_raw: String,
        new_raw: String,
        basis: String,
        reason: String,
    },
    /// 只影响局部依赖的源数据改动：替换某个 DLL export 快照。
    SourceAmendment {
        target_dll: String,
        old_label: String,
        new_label: String,
        reason: String,
    },
    /// 互相冲突的人工决定：对一个候选的接受/否定。
    ArtifactDecision {
        artifact_id: String,
        candidate_id: String,
        /// accept | reject
        verdict: String,
        reason: String,
    },
    /// 撤销某次裁定（补偿事件，恢复前一分支）。
    DecisionReversal {
        reversed_event_id: String,
        artifact_id: String,
        candidate_id: String,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRecord {
    pub id: String,
    pub parent_id: Option<String>,
    pub seq: i64,
    pub branch_id: String,
    pub rule_version: String,
    pub author: String,
    pub created_at: String,
    pub payload: EventPayload,
}

/// 分支：分支只是事件链上的命名指针；旧分支、裁定与它们引用的字节始终可读。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchRecord {
    pub id: String,
    pub name: String,
    pub tip_event_id: String,
    pub created_at: String,
}
