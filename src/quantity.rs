//! Domain quantities keep their raw representation. Normalization happens in
//! the derived layer only; values that cannot be converted stay in place and
//! carry a diagnostic.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quantity {
    pub raw: String,
    pub unit: String,
    pub basis: String,
    pub value: Option<u64>,
    pub diagnostic: Option<String>,
}

pub fn parse_u64(raw: &str, unit: &str, basis: &str) -> Quantity {
    let t = raw.trim();
    let parsed = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else if let Some(h) = t.strip_prefix('#') {
        u64::from_str_radix(h, 16).ok()
    } else {
        t.parse::<u64>().ok()
    };
    Quantity {
        raw: raw.to_string(),
        unit: unit.into(),
        basis: basis.into(),
        value: parsed,
        diagnostic: if parsed.is_none() {
            Some(format!("cannot normalize {:?} as u64 ({} / {})", raw, unit, basis))
        } else {
            None
        },
    }
}
