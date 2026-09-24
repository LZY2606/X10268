use serde::{Deserialize, Serialize};

/// A domain quantity. The raw representation is always preserved; the
/// normalized value lives only in the derived layer. Unconvertible values
/// keep `value: None` and stay in place with their raw text.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Quantity {
    pub raw: String,
    pub value: Option<u64>,
    pub unit: String,
    /// Coordinate basis: "file_offset" | "rva" | "va" | "count" | "bytes"
    pub basis: String,
}

impl Quantity {
    pub fn of(raw: impl Into<String>, value: u64, unit: &str, basis: &str) -> Self {
        Quantity {
            raw: raw.into(),
            value: Some(value),
            unit: unit.into(),
            basis: basis.into(),
        }
    }
    pub fn hex(value: u64, unit: &str, basis: &str) -> Self {
        Quantity::of(format!("0x{value:08X}"), value, unit, basis)
    }
    pub fn bad(raw: impl Into<String>, unit: &str, basis: &str) -> Self {
        Quantity {
            raw: raw.into(),
            value: None,
            unit: unit.into(),
            basis: basis.into(),
        }
    }
}

/// Parse a raw numeric string ("0x1A00" or decimal). Returns None when the
/// value cannot be converted; callers must keep the raw text and attach a
/// diagnostic instead of dropping it.
pub fn parse_num(raw: &str) -> Option<u64> {
    let t = raw.trim();
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else {
        t.parse::<u64>().ok()
    }
}
