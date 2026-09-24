//! Core domain types: coordinates, provenance, raw facts, snapshots, diagnostics.
//!
//! Rule: imported materials keep their *original representation* (raw bytes /
//! verbatim JSON). Normalisation to RVAs/VAs and other derived quantities only
//! happens in the interpretation layer (`engine`).

use serde::{Deserialize, Serialize};

/// A domain quantity tagged with its coordinate base / unit so values can never
/// be silently mixed (file offset vs RVA vs VA).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Q {
    pub value: u64,
    pub unit: Unit,
}

impl Q {
    pub fn file(v: u64) -> Self {
        Q { value: v, unit: Unit::ByteFile }
    }
    pub fn rva(v: u64) -> Self {
        Q { value: v, unit: Unit::ByteRva }
    }
    pub fn va(v: u64) -> Self {
        Q { value: v, unit: Unit::ByteVa }
    }
    pub fn ordinal(v: u64) -> Self {
        Q { value: v, unit: Unit::Ordinal }
    }
    pub fn count(v: u64) -> Self {
        Q { value: v, unit: Unit::Count }
    }
    pub fn delta(v: i64) -> Self {
        Q { value: v as u64, unit: Unit::RelocDelta }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unit {
    /// Byte offset measured from the start of the file image.
    #[serde(rename = "byte/file-offset")]
    ByteFile,
    /// Byte offset measured from the image base (relative virtual address).
    #[serde(rename = "byte/rva")]
    ByteRva,
    /// Absolute virtual address (image base + RVA).
    #[serde(rename = "byte/va")]
    ByteVa,
    /// Export ordinal, dimensionless index with its own base (ordinal table).
    #[serde(rename = "ordinal")]
    Ordinal,
    /// Number of items / entries.
    #[serde(rename = "count")]
    Count,
    /// Signed relocation delta (image base difference), in bytes.
    #[serde(rename = "byte/relocation-delta")]
    RelocDelta,
}

/// Byte-level provenance pointer: where a fact came from in an imported blob.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Span {
    pub material_id: String,
    /// File offset of the first source byte.
    pub file_offset: u64,
    /// Number of source bytes.
    pub length: u64,
}

/// A single field read from a material. `repr` keeps the original on-disk bytes
/// (hex, little-endian order as stored); `value` is the parsed interpretation.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RawField {
    pub name: String,
    pub value: serde_json::Value,
    /// Hex of the original bytes exactly as stored in the source material.
    pub repr: String,
    pub span: Option<Span>,
}

/// A structured fact extracted directly from bytes (headers, section table row,
/// data directory, relocation block/entry, import descriptor/thunk/name).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RawRecord {
    pub id: String,
    pub kind: RawKind,
    pub ordinal: u32,
    pub title: String,
    pub fields: Vec<RawField>,
    pub spans: Vec<Span>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum RawKind {
    #[serde(rename = "dos_header")]
    DosHeader,
    #[serde(rename = "nt_headers")]
    NtHeaders,
    #[serde(rename = "section")]
    Section,
    #[serde(rename = "data_directory")]
    DataDirectory,
    #[serde(rename = "relocation_block")]
    RelocationBlock,
    #[serde(rename = "relocation_entry")]
    RelocationEntry,
    #[serde(rename = "import_descriptor")]
    ImportDescriptor,
    #[serde(rename = "import_thunk")]
    ImportThunk,
    #[serde(rename = "dll_name")]
    DllName,
    #[serde(rename = "import_name")]
    ImportName,
}

/// A diagnostic produced while interpreting materials. It never destroys the
/// underlying fact: unconvertible values stay in place with a diagnostic.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Diag {
    pub code: String,
    pub severity: DiagSeverity,
    pub message: String,
    pub span: Option<Span>,
    pub rva: Option<Q>,
    /// Logical object (derived node id / record id) this diagnostic belongs to.
    pub object_id: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagSeverity {
    #[serde(rename = "error")]
    Error,
    #[serde(rename = "warning")]
    Warning,
}

// ---- Deterministic parsed structures --------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DosHeader {
    pub e_lfanew: u64,
    pub fields: Vec<RawField>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NtHeaders {
    pub machine: u16,
    pub pe32_plus: bool,
    pub image_base: u64,
    pub size_of_image: u64,
    pub size_of_headers: u64,
    pub section_alignment: u64,
    pub file_alignment: u64,
    pub num_sections: u16,
    pub fields: Vec<RawField>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Section {
    pub index: u32,
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_offset: u64,
    pub raw_size: u64,
    pub characteristics: u32,
    pub fields: Vec<RawField>,
    pub hdr_span: Span,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DataDirectory {
    pub index: u32,
    pub label: String,
    pub rva: u64,
    pub size: u64,
    pub field: RawField,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RelocEntryRaw {
    pub block_index: u32,
    pub index: u32,
    pub raw_type: u8,
    pub offset: u16,
    pub rva: u64,
    pub field: RawField,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RelocBlockRaw {
    pub index: u32,
    pub page_rva: u64,
    pub block_size: u64,
    pub entries: Vec<RelocEntryRaw>,
    pub fields: Vec<RawField>,
    pub span: Span,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ImportThunkRaw {
    pub desc_index: u32,
    pub index: u32,
    pub ilt_value: u64,
    pub iat_value: u64,
    pub is_ordinal: bool,
    pub ordinal: Option<u16>,
    pub hint_name_rva: Option<u64>,
    pub hint: Option<u16>,
    pub name: Option<String>,
    pub ilt_span: Option<Span>,
    pub iat_span: Option<Span>,
    pub name_span: Option<Span>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
/// One legal interpretation of an RVA that resolves through more than one
/// section (overlap) or zero-fill. All variants are retained.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NameVariant {
    pub value: String,
    pub section_index: u32,
    pub section_name: String,
    pub file_offset: Option<u64>,
    pub backing: String,
}

pub struct ImportDescRaw {
    pub index: u32,
    pub original_first_thunk: u64,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name_rva: u64,
    pub first_thunk: u64,
    pub name: Option<String>,
    pub name_span: Option<Span>,
    pub name_variants: Vec<NameVariant>,
    pub thunks: Vec<ImportThunkRaw>,
    pub fields: Vec<RawField>,
    pub span: Span,
    /// True when this descriptor's bytes could not be read from one unique
    /// file location (unmapped / overlapping candidates).
    pub unreadable: bool,
}

/// The deterministic structural facts parsed from a PE material.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct PeFacts {
    pub pe_material_id: String,
    pub dos: Option<DosHeader>,
    pub nt: Option<NtHeaders>,
    pub sections: Vec<Section>,
    pub directories: Vec<DataDirectory>,
    pub reloc_blocks: Vec<RelocBlockRaw>,
    pub import_descs: Vec<ImportDescRaw>,
    pub raw_records: Vec<RawRecord>,
    pub diagnostics: Vec<Diag>,
}

// ---- DLL export snapshots --------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ExportEntry {
    pub name: Option<String>,
    pub ordinal: u32,
    pub forwarder: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Snapshot {
    pub material_id: String,
    /// DLL key as normalised for lookup (uppercase). Retained alongside the
    /// original spelling stored in the material bytes.
    pub dll_key: String,
    pub dll_name: String,
    pub exports: Vec<ExportEntry>,
}

// ---- Materials -------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaterialKind {
    #[serde(rename = "pe")]
    Pe,
    #[serde(rename = "snapshot")]
    Snapshot,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Material {
    pub id: String,
    pub kind: MaterialKind,
    pub filename: String,
    pub sha256: String,
    /// Original bytes are retained verbatim (PE blob or snapshot JSON text).
    pub bytes: Vec<u8>,
}
