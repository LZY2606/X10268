//! Domain quantities with explicit units / coordinate bases.
//! Raw textual representation is preserved at import; normalization
//! happens only in the derived layer. Unconvertible values stay in
//! place and carry a diagnostic.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Unit {
    Rva,      // relative to image base
    Va,       // absolute virtual address (basis: image base)
    FileOff,  // offset into the file bytes
    Bytes,    // a size
    Count,
    Ordinal,
    None,
}

impl Unit {
    pub fn as_str(&self) -> &'static str {
        match self {
            Unit::Rva => "rva",
            Unit::Va => "va",
            Unit::FileOff => "fileoff",
            Unit::Bytes => "bytes",
            Unit::Count => "count",
            Unit::Ordinal => "ordinal",
            Unit::None => "none",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Qty {
    /// Original representation exactly as imported (e.g. "0x1000").
    pub raw: String,
    /// Normalized value; None when it could not be converted.
    pub value: Option<u64>,
    pub unit: Unit,
    /// Coordinate basis, e.g. "image_base=0x140000000" for Va.
    pub basis: Option<String>,
    /// Diagnostic attached when conversion failed or is suspicious.
    pub diagnostic: Option<String>,
}

impl Qty {
    pub fn new(value: u64, unit: Unit) -> Self {
        Qty { raw: format!("0x{value:x}"), value: Some(value), unit, basis: None, diagnostic: None }
    }
    pub fn rva(v: u64) -> Self { Qty::new(v, Unit::Rva) }
    pub fn fileoff(v: u64) -> Self { Qty::new(v, Unit::FileOff) }
    pub fn bytes(v: u64) -> Self { Qty::new(v, Unit::Bytes) }
    pub fn count(v: u64) -> Self { Qty::new(v, Unit::Count) }
    pub fn ordinal(v: u64) -> Self { Qty::new(v, Unit::Ordinal) }

    /// Parse a raw representation; never fails — unconvertible input
    /// stays in `raw` with a diagnostic attached.
    pub fn parse(raw: &str, unit: Unit) -> Self {
        let t = raw.trim();
        let parsed = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
            u64::from_str_radix(h, 16).ok()
        } else {
            t.parse::<u64>().ok()
        };
        let diagnostic = if parsed.is_none() {
            Some(format!("cannot normalize {raw:?} as {}", unit.as_str()))
        } else { None };
        Qty { raw: raw.to_string(), value: parsed, unit, basis: None, diagnostic }
    }

    pub fn va_with_basis(v: u64, image_base: u64) -> Self {
        let mut q = Qty::new(v, Unit::Va);
        q.basis = Some(format!("image_base=0x{image_base:x}"));
        q
    }
}

pub fn hex(v: u64) -> String { format!("0x{v:x}") }

/// Render a quantity for the UI: raw representation plus unit/basis.
pub fn render_qty(q: &Qty) -> String {
    let mut s = format!("{} [{}]", q.raw, q.unit.as_str());
    if let Some(b) = &q.basis { s.push_str(&format!(" ({b})")); }
    if let Some(d) = &q.diagnostic { s.push_str(&format!(" !! {d}")); }
    s
}
