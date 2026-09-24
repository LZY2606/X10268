//! PE 解析：只做“解释”，不做不可逆清洗。
//!
//! 每个解析值都同时保留：
//!   - raw 原始表示（例如 "0x00400000"）
//!   - basis 坐标基准（file/rva/va/raw-size/virtual-size/scalar）
//!   - span 字节来源（blob 内 [start,end)）
//! 无法读取/转换的值原地保留并附 diagnostic，而不是丢弃。

use crate::types::{Basis, ByteSpan, Diagnostic, RawValue};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fact {
    pub stable_id: String,
    pub kind: String,
    pub ord: i64,
    pub coordinate: String,
    pub value: RawValue,
    pub span: Option<ByteSpan>,
    pub extra: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct ParsedPE {
    pub facts: Vec<Fact>,
    pub diagnostics: Vec<(String, Diagnostic)>,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub file_align: u32,
    pub sect_align: u32,
    pub image_base: u64,
    pub pe32_plus: bool,
    pub sections: Vec<ParsedSection>,
    pub directories: Vec<ParsedDirectory>,
    pub reloc_blocks: Vec<ParsedRelocBlock>,
    pub imports: Vec<ParsedImport>,
}

#[derive(Debug, Clone)]
pub struct ParsedSection {
    pub index: usize,
    pub name: String,
    pub vaddr: u32,
    pub vsize: u32,
    pub rawptr: u32,
    pub rawsize: u32,
    pub characteristics: u32,
    pub name_span: (u64, u64),
}

#[derive(Debug, Clone)]
pub struct ParsedDirectory {
    pub index: usize,
    pub rva: u32,
    pub size: u32,
    pub rva_span: (u64, u64),
    pub size_span: (u64, u64),
}

#[derive(Debug, Clone)]
pub struct ParsedRelocBlock {
    pub index: usize,
    pub page_rva: u32,
    pub size_of_block: u32,
    pub span: (u64, u64),
    pub entries: Vec<ParsedRelocEntry>,
}

#[derive(Debug, Clone)]
pub struct ParsedRelocEntry {
    pub block: usize,
    pub index: usize,
    pub raw_type: u8,
    pub offset: u16,
    pub target_rva: u32,
    pub span: (u64, u64),
}

#[derive(Debug, Clone)]
pub struct ParsedImport {
    pub dll: String,
    pub desc_index: usize,
    pub name_rva: u32,
    pub ilt_rva: u32,
    pub iat_rva: u32,
    pub thunks: Vec<ParsedThunk>,
}

#[derive(Debug, Clone)]
pub struct ParsedThunk {
    pub index: usize,
    pub is_ordinal: bool,
    pub ordinal: Option<u16>,
    pub hint_name_rva: Option<u32>,
    pub hint: Option<u16>,
    pub name: Option<String>,
    pub raw_thunk: String,
    pub thunk_span: Option<(u64, u64)>,
}

struct Cursor<'a> {
    b: &'a [u8],
    diag: Vec<(String, Diagnostic)>,
}

impl<'a> Cursor<'a> {
    fn new(b: &'a [u8]) -> Self { Cursor { b, diag: Vec::new() } }
    fn u16(&mut self, at: usize, ctx: &str) -> Option<u16> {
        if at + 2 > self.b.len() {
            self.diag.push((ctx.to_string(), Diagnostic::new(
                "OUT_OF_FILE", format!("读取 u16 @0x{at:X} 超出文件长度 0x{:X}", self.b.len()))));
            None
        } else { Some(u16::from_le_bytes([self.b[at], self.b[at + 1]])) }
    }
    fn u32(&mut self, at: usize, ctx: &str) -> Option<u32> {
        if at + 4 > self.b.len() {
            self.diag.push((ctx.to_string(), Diagnostic::new(
                "OUT_OF_FILE", format!("读取 u32 @0x{at:X} 超出文件长度 0x{:X}", self.b.len()))));
            None
        } else { Some(u32::from_le_bytes(self.b[at..at + 4].try_into().unwrap())) }
    }
    fn u64(&mut self, at: usize, ctx: &str) -> Option<u64> {
        if at + 8 > self.b.len() {
            self.diag.push((ctx.to_string(), Diagnostic::new(
                "OUT_OF_FILE", format!("读取 u64 @0x{at:X} 超出文件长度 0x{:X}", self.b.len()))));
            None
        } else { Some(u64::from_le_bytes(self.b[at..at + 8].try_into().unwrap())) }
    }
}

fn hex_u16(v: u16) -> String { format!("0x{:04X}", v) }
fn hex_u32(v: u32) -> String { format!("0x{:08X}", v) }
fn hex_u64(v: u64) -> String { format!("0x{:016X}", v) }

/// 解析 PE 字节。blob_id 用于生成字节来源 span。
pub fn parse_pe(bytes: &[u8], blob_id: &str) -> ParsedPE {
    let mut c = Cursor::new(bytes);
    let mut facts: Vec<Fact> = Vec::new();
    let mut ord = 0i64;
    let mut push = |facts: &mut Vec<Fact>, ord: &mut i64,
                    kind: &str, coord: &str, value: RawValue,
                    span: Option<(u64, u64)>, extra: serde_json::Value| {
        *ord += 1;
        facts.push(Fact {
            stable_id: format!("fact:{kind}:{coord}"),
            kind: kind.to_string(),
            ord: *ord,
            coordinate: coord.to_string(),
            value,
            span: span.map(|(s, e)| ByteSpan { blob_id: blob_id.to_string(), start: s, end: e }),
            extra,
        });
    };

    // DOS header：保留 MZ 与 e_lfanew 的原始字节。
    let mz = if bytes.len() >= 2 { [bytes[0] as char, bytes[1] as char] } else { ['?', '?'] };
    push(&mut facts, &mut ord, "dos_header", "signature",
         RawValue::new(0x5A4D, format!("{}{}", mz[0], mz[1]), Basis::Scalar),
         Some((0, 2)), serde_json::json!({"raw_ascii": format!("{}{}", mz[0], mz[1])}));
    let e_lfanew = c.u32(0x3C, "dos_header.e_lfanew").unwrap_or(0);
    push(&mut facts, &mut ord, "dos_header", "e_lfanew",
         RawValue::new(e_lfanew as i64, hex_u32(e_lfanew), Basis::FileByte),
         Some((0x3C, 0x40)), serde_json::json!({}));

    let pe = e_lfanew as usize;
    let sig_ok = pe + 4 <= bytes.len() && &bytes[pe..pe + 4] == b"PE\0\0";
    if !sig_ok {
        c.diag.push(("nt_header.signature".into(), Diagnostic::new(
            "BAD_PE_SIGNATURE", format!("@{:#X} 不是 PE\\0\\0", pe))));
    }
    push(&mut facts, &mut ord, "nt_header", "signature",
         RawValue::new(0x00004550, "PE\\0\\0", Basis::Scalar),
         Some((pe as u64, pe as u64 + 4)),
         serde_json::json!({"valid": sig_ok}));

    let coff = pe + 4;
    let machine = c.u16(coff + 0, "coff.machine");
    let nsec = c.u16(coff + 2, "coff.number_of_sections").unwrap_or(0);
    let size_opt = c.u16(coff + 16, "coff.size_of_optional_header").unwrap_or(0xE0);
    let characteristics = c.u16(coff + 18, "coff.characteristics").unwrap_or(0);
    push(&mut facts, &mut ord, "coff", "machine",
         RawValue::new(machine.unwrap_or(0) as i64, machine.map(hex_u16).unwrap_or_else(|| "<?>".into()), Basis::Scalar),
         Some(((coff) as u64, coff as u64 + 2)), serde_json::json!({}));
    push(&mut facts, &mut ord, "coff", "number_of_sections",
         RawValue::new(nsec as i64, nsec.to_string(), Basis::Scalar),
         Some((coff as u64 + 2, coff as u64 + 4)), serde_json::json!({}));
    push(&mut facts, &mut ord, "coff", "characteristics",
         RawValue::new(characteristics as i64, hex_u16(characteristics), Basis::Scalar),
         Some((coff as u64 + 18, coff as u64 + 20)), serde_json::json!({}));

    let opt = coff + 20;
    let magic = c.u16(opt + 0, "optional.magic").unwrap_or(0x10B);
    let pe32_plus = magic == 0x20B;
    push(&mut facts, &mut ord, "optional_header", "magic",
         RawValue::new(magic as i64, hex_u16(magic), Basis::Scalar),
         Some((opt as u64, opt as u64 + 2)),
         serde_json::json!({"pe32_plus": pe32_plus}));

    let image_base: u64 = if pe32_plus {
        c.u64(opt + 24, "optional.image_base").unwrap_or(0)
    } else {
        c.u32(opt + 28, "optional.image_base").unwrap_or(0) as u64
    };
    let ib_span = if pe32_plus { (opt + 24, opt + 32) } else { (opt + 28, opt + 32) };
    push(&mut facts, &mut ord, "optional_header", "image_base",
         RawValue::new(image_base as i64, hex_u64(image_base), Basis::VaByte),
         Some((ib_span.0 as u64, ib_span.1 as u64)), serde_json::json!({}));
    let sect_align = c.u32(opt + 32, "optional.section_alignment").unwrap_or(0x1000);
    let file_align = c.u32(opt + 36, "optional.file_alignment").unwrap_or(0x200);
    let size_image = c.u32(opt + 56, "optional.size_of_image").unwrap_or(0);
    let size_headers = c.u32(opt + 60, "optional.size_of_headers").unwrap_or(0);
    push(&mut facts, &mut ord, "optional_header", "section_alignment",
         RawValue::new(sect_align as i64, hex_u32(sect_align), Basis::RvaByte),
         Some((opt as u64 + 32, opt as u64 + 36)), serde_json::json!({}));
    push(&mut facts, &mut ord, "optional_header", "file_alignment",
         RawValue::new(file_align as i64, hex_u32(file_align), Basis::FileByte),
         Some((opt as u64 + 36, opt as u64 + 40)), serde_json::json!({}));
    push(&mut facts, &mut ord, "optional_header", "size_of_image",
         RawValue::new(size_image as i64, hex_u32(size_image), Basis::RvaByte),
         Some((opt as u64 + 56, opt as u64 + 60)), serde_json::json!({}));
    push(&mut facts, &mut ord, "optional_header", "size_of_headers",
         RawValue::new(size_headers as i64, hex_u32(size_headers), Basis::FileByte),
         Some((opt as u64 + 60, opt as u64 + 64)), serde_json::json!({}));

    // Data directory（PE32/PE32+ 均从 opt+96 开始，每项 8 字节）。
    let dir = opt + 96;
    let mut directories = Vec::new();
    for i in 0..16u32 {
        let at = dir + (i * 8) as usize;
        let rva = c.u32(at, &format!("data_directory[{i}].rva")).unwrap_or(0);
        let size = c.u32(at + 4, &format!("data_directory[{i}].size")).unwrap_or(0);
        directories.push(ParsedDirectory { index: i as usize, rva, size,
            rva_span: (at as u64, at as u64 + 4), size_span: (at as u64 + 4, at as u64 + 8) });
        push(&mut facts, &mut ord, "data_directory", &format!("dir{:02}.rva", i),
             RawValue::new(rva as i64, hex_u32(rva), Basis::RvaByte),
             Some((at as u64, at as u64 + 4)),
             serde_json::json!({"directory_index": i, "field": "rva", "size_raw": hex_u32(size)}));
    }

    // Section headers。
    let mut sections = Vec::new();
    let mut sh = opt + size_opt as usize;
    for i in 0..nsec as usize {
        let at = sh + i * 40;
        let raw_name: Vec<u8> = bytes[at..at + 8].iter().take_while(|&&x| x != 0).copied().collect();
        let name = String::from_utf8_lossy(&raw_name).to_string();
        let vsize = c.u32(at + 8, &format!("section[{i}].virtual_size")).unwrap_or(0);
        let vaddr = c.u32(at + 12, &format!("section[{i}].virtual_address")).unwrap_or(0);
        let rawsize = c.u32(at + 16, &format!("section[{i}].size_of_raw_data")).unwrap_or(0);
        let rawptr = c.u32(at + 20, &format!("section[{i}].pointer_to_raw_data")).unwrap_or(0);
        let chars = c.u32(at + 36, &format!("section[{i}].characteristics")).unwrap_or(0);
        sections.push(ParsedSection { index: i, name: name.clone(), vaddr, vsize, rawptr, rawsize,
            characteristics: chars, name_span: (at as u64, at as u64 + 8) });

        push(&mut facts, &mut ord, "section", &format!("sec{i}.name"),
             RawValue::new(i as i64, name.clone(), Basis::Scalar),
             Some((at as u64, at as u64 + 8)), serde_json::json!({}));
        push(&mut facts, &mut ord, "section", &format!("sec{i}.virtual_address"),
             RawValue::new(vaddr as i64, hex_u32(vaddr), Basis::RvaByte),
             Some((at as u64 + 12, at as u64 + 16)), serde_json::json!({"section": name}));
        push(&mut facts, &mut ord, "section", &format!("sec{i}.virtual_size"),
             RawValue::new(vsize as i64, hex_u32(vsize), Basis::VirtualSizeByte),
             Some((at as u64 + 8, at as u64 + 12)), serde_json::json!({"section": name}));
        push(&mut facts, &mut ord, "section", &format!("sec{i}.pointer_to_raw_data"),
             RawValue::new(rawptr as i64, hex_u32(rawptr), Basis::FileByte),
             Some((at as u64 + 20, at as u64 + 24)), serde_json::json!({"section": name}));
        push(&mut facts, &mut ord, "section", &format!("sec{i}.size_of_raw_data"),
             RawValue::new(rawsize as i64, hex_u32(rawsize), Basis::RawSizeByte),
             Some((at as u64 + 16, at as u64 + 20)), serde_json::json!({"section": name}));
        push(&mut facts, &mut ord, "section", &format!("sec{i}.characteristics"),
             RawValue::new(chars as i64, hex_u32(chars), Basis::Scalar),
             Some((at as u64 + 36, at as u64 + 40)), serde_json::json!({"section": name}));
    }
