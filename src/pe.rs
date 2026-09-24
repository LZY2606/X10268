//! PE 解析层：只负责把字节切成结构，并为每个字段保留字节来源（文件偏移坐标）。
//! 不做任何不可逆清洗；损坏的 data directory 只产生诊断，不中断整体解析。

use serde::{Deserialize, Serialize};

/// 字节区间：坐标基准为文件偏移（file offset），单位为字节。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Span {
    pub off: u64,
    pub len: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Diagnostic {
    pub code: String,
    pub message: String,
    pub src: Option<Span>,
}

#[derive(Clone, Debug to Serialize, Deserialize)]
pub struct DosHeader {
    pub e_magic: u16,
    pub e_lfanew: u32,
    pub src: Span,
}
