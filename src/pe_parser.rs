//! PE 解析：不做不可逆清洗。所有结构化事实附带字节来源（文件偏移区间），
//! 无法读取/转换的值留在原位并产生 diagnostic。

use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Default)]
pub struct Span {
    /// 坐标基准：始终是文件偏移（file-offset），单位 byte
    pub basis: &'static str,
    pub start: usize,
    pub len: usize,
}

impl Span {
    pub const fn file(start: usize, len: usize) -> Self {
        Self { basis: "byte/file-offset", start, len }
    }
    pub fn end(&self) -> usize { self.start + self.len }
}

#[derive(Debug, Clone, Serialize)]
pub struct Field<T: Serialize + Clone> {
    pub key: &'static str,
    pub raw: String,
    pub value: Option<T>,
    pub unit: &'static str,
    pub span: Span,
}

impl<T: Serialize + Clone> Default for Field<T> {
    fn default() -> Self {
        Self { key: "", raw: String::new(), value: None, unit: "", span: Span::default() }
    }
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct DosHeader {
    pub mz: String,
    pub e_lfanew: Field<u32>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct FileHeader {
    pub machine: Field<u16>,
    pub number_of_sections: Field<u16>,
    pub time_date_stamp: Field<u32>,
    pub size_of_optional_header: Field<u16>,
    pub characteristics: Field<u16>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct OptionalHeader {
    pub magic: Field<u16>,
    pub image_base: Field<u64>,
    pub section_alignment: Field<u32>,
    pub file_alignment: Field<u32>,
    pub size_of_image: Field<u32>,
    pub size_of_headers: Field<u32>,
    pub number_of_rva_and_sizes: Field<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SectionHeader {
    pub ordinal: usize,
    pub name: String,
    pub virtual_size: Field<u32>,
    pub virtual_address: Field<u32>,
    pub size_of_raw_data: Field<u32>,
    pub pointer_to_raw_data: Field<u32>,
    pub characteristics: Field<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DataDirectoryFact {
    pub ordinal: usize,
    pub known_name: String,
    pub rva: Field<u32>,
    pub size: Field<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelocEntry {
    pub index: usize,
    pub type_name: String,
    pub type_raw: u8,
    pub offset_in_page: u16,
    pub rva: u32,
    pub width_bytes: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelocBlock {
    pub index: usize,
    pub page_rva: u32,
    pub block_size: u32,
    pub entries: Vec<RelocEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportThunk {
    pub index: usize,
    pub ilt_slot_rva: u32,
    pub iat_slot_rva: u32,
    pub is_ordinal: bool,
    pub ordinal: Option<u16>,
    pub hint: Option<u16>,
    pub name: Option<String>,
    pub hint_name_rva: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportDescriptor {
    pub index: usize,
    pub dll_name: String,
    pub original_first_thunk_rva: u32,
    pub first_thunk_rva: u32,
    pub iat_size_hint: u32,
    pub thunks: Vec<ImportThunk>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Diagnostic {
    pub code: String,
    pub severity: String,
    pub message: String,
    pub span: Option<Span>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeFacts {
    pub dos: DosHeader,
    pub file_hdr: FileHeader,
    pub opt: OptionalHeader,
    pub sections: Vec<SectionHeader>,
    pub directories: Vec<DataDirectoryFact>,
    pub reloc_blocks: Vec<RelocBlock>,
    pub imports: Vec<ImportDescriptor>,
    pub diagnostics: Vec<Diagnostic>,
}

pub const DIR_IMPORT: usize = 1;
pub const DIR_BASERELOC: usize = 5;
pub const DIR_IAT: usize = 12;

struct Ctx<'a> {
    b: &'a [u8],
    diag: Vec<Diagnostic>,
}

impl<'a> Ctx<'a> {
    fn need(&mut self, off: usize, len: usize) -> Option<&'a [u8]> {
        if off.checked_add(len).map(|e| e <= self.b.len()).unwrap_or(false) {
            Some(&self.b[off..off + len])
        } else {
            self.diag.push(Diagnostic {
                code: "PE_READ_OUT_OF_FILE".into(),
                severity: "error".into(),
                message: format!("读取 [file-offset {} +{} bytes] 超出文件长度 {}", off, len, self.b.len()),
                span: Some(Span::file(off, len)),
            });
            None
        }
    }
    fn u16(&mut self, off: usize, key: &'static str, unit: &'static str) -> Field<u16> {
        let bytes = self.need(off, 2);
        let raw = bytes.map(|x| format!("0x{:04X}", u16::from_le_bytes([x[0], x[1]]))).unwrap_or_else(|| "?".into());
        let value = bytes.map(|x| u16::from_le_bytes([x[0], x[1]]));
        Field { key, raw, value, unit, span: Span::file(off, 2) }
    }
    fn u32f(&mut self, off: usize, key: &'static str, unit: &'static str) -> Field<u32> {
        let bytes = self.need(off, 4);
        let raw = bytes.map(|x| format!("0x{:08X}", u32::from_le_bytes(x.try_into().unwrap()))).unwrap_or_else(|| "?".into());
        let value = bytes.map(|x| u32::from_le_bytes(x.try_into().unwrap()));
        Field { key, raw, value, unit, span: Span::file(off, 4) }
    }
    fn u64f(&mut self, off: usize, key: &'static str, unit: &'static str) -> Field<u64> {
        let bytes = self.need(off, 8);
        let raw = bytes.map(|x| format!("0x{:016X}", u64::from_le_bytes(x.try_into().unwrap()))).unwrap_or_else(|| "?".into());
        let value = bytes.map(|x| u64::from_le_bytes(x.try_into().unwrap()));
        Field { key, raw, value, unit, span: Span::file(off, 8) }
    }
}

fn reloc_type(t: u8) -> (&'static str, u8) {
    match t {
        0 => ("ABSOLUTE", 0),
        1 | 2 | 4 | 5 => ("HIGHADJ_CLASS", 2),
        3 => ("HIGHLOW", 4),
        7 => ("MIPS_JMPADDR", 4),
        9 => ("DIR64", 8),
        10 => ("HIGH3ADJ", 2),
        other => ("UNKNOWN", { let _ = other; 0 }),
    }
}

fn cstring_at(b: &[u8], rva: u32, sections: &[SectionHeader]) -> Option<String> {
    // 仅按 raw 指针读取，不假定 RVA 唯一映射；返回命中的第一段字节。
    for s in sections {
        let va = s.virtual_address.value?;
        let vs = s.virtual_size.value?;
        let rp = s.pointer_to_raw_data.value?;
        let rs = s.size_of_raw_data.value?;
        if rva >= va && rva < va + vs {
            let d = rva - va;
            if d < rs {
                let start = rp as usize + d as usize;
                let mut end = start;
                while end < b.len() && b[end] != 0 { end += 1; }
                return String::from_utf8(b[start..end].to_vec()).ok();
            }
        }
    }
    None
}

fn read_u64_via_raw(b: &[u8], rva: u32, sections: &[SectionHeader]) -> Option<u64> {
    for s in sections {
        let va = s.virtual_address.value?;
        let vs = s.virtual_size.value?;
        let rp = s.pointer_to_raw_data.value?;
        let rs = s.size_of_raw_data.value?;
        if rva >= va && rva < va + vs {
            let d = rva - va;
            if d + 8 <= rs {
                let start = rp as usize + d as usize;
                return Some(u64::from_le_bytes(b[start..start + 8].try_into().ok()?));
            }
        }
    }
    None
}

pub fn known_dir_name(i: usize) -> String {
    match i {
        0 => "Export".into(), 1 => "Import".into(), 3 => "Exception".into(),
        5 => "BaseReloc".into(), 6 => "Debug".into(), 12 => "IAT".into(),
        13 => "BoundImport".into(), 14 => "IAT?DelayImport".into(),
        _ => format!("Directory[{}]", i),
    }
}

pub fn parse_pe(b: &[u8]) -> PeFacts {
    let mut c = Ctx { b, diag: Vec::new() };
    let mut facts = PeFacts {
        dos: DosHeader::default(),
        file_hdr: FileHeader::default(),
        opt: OptionalHeader::default(),
        sections: Vec::new(),
        directories: Vec::new(),
        reloc_blocks: Vec::new(),
        imports: Vec::new(),
        diagnostics: Vec::new(),
    };

    // DOS
    let mz = if b.len() >= 2 { format!("{}{}", b[0] as char, b[1] as char) } else { "??".into() };
    if mz != "MZ" {
        c.diag.push(Diagnostic { code: "PE_BAD_MZ".into(), severity: "error".into(),
            message: format!("DOS magic 不是 MZ：{}", mz), span: Some(Span::file(0, 2)) });
    }
    facts.dos.mz = mz;
    let e_lfanew = c.u32f(0x3C, "e_lfanew", "byte/file-offset");
    let nt = match e_lfanew.value { Some(v) => v as usize, None => 0x80 };
    facts.dos.e_lfanew = e_lfanew;

    if c.need(nt, 4) != Some(&b"PE\0\0"[..]) {
        c.diag.push(Diagnostic { code: "PE_BAD_NT_SIG".into(), severity: "error".into(),
            message: "NT signature 不是 PE\\0\\0\\0".into(), span: Some(Span::file(nt, 4)) });
    }
    let fh = nt + 4;
    facts.file_hdr.machine = c.u16(fh + 0, "Machine", "u16/enum");
    facts.file_hdr.number_of_sections = c.u16(fh + 2, "NumberOfSections", "count");
    facts.file_hdr.time_date_stamp = c.u32f(fh + 4, "TimeDateStamp", "u32/unix-seconds");
    facts.file_hdr.size_of_optional_header = c.u16(fh + 2 + 16, "SizeOfOptionalHeader", "byte");
    facts.file_hdr.characteristics = c.u16(fh + 2 + 18, "Characteristics", "u16/bitflags");

    let oh = fh + 20;
    facts.opt.magic = c.u16(oh + 0, "Magic", "u16/enum");
    facts.opt.image_base = c.u64f(oh + 0x18, "ImageBase", "u64-absolute-va");
    facts.opt.section_alignment = c.u32f(oh + 0x20, "SectionAlignment", "byte");
    facts.opt.file_alignment = c.u32f(oh + 0x24, "FileAlignment", "byte");
    facts.opt.size_of_image = c.u32f(oh + 0x38, "SizeOfImage", "byte/va-extent");
    facts.opt.size_of_headers = c.u32f(oh + 0x3C, "SizeOfHeaders", "byte/file-extent");
    facts.opt.number_of_rva_and_sizes = c.u32f(oh + 0x6C, "NumberOfRvaAndSizes", "count");

    // 节表：PE32+ 可选头固定 240 字节，节表紧跟其后
    let nsec = facts.file_hdr.number_of_sections.value.unwrap_or(0) as usize;
    let sh0 = oh + 0xF0;
    for i in 0..nsec {
        let off = sh0 + i * 40;
        let raw_name = c.need(off, 8).map(|x| x.to_vec()).unwrap_or_default();
        let nz = raw_name.iter().position(|&x| x == 0).unwrap_or(raw_name.len());
        let name = String::from_utf8_lossy(&raw_name[..nz]).to_string();
        facts.sections.push(SectionHeader {
            ordinal: i,
            name,
            virtual_size: c.u32f(off + 0x08, "VirtualSize", "byte/va-extent"),
            virtual_address: c.u32f(off + 0x0C, "VirtualAddress", "rva32"),
            size_of_raw_data: c.u32f(off + 0x10, "SizeOfRawData", "byte/file-extent"),
            pointer_to_raw_data: c.u32f(off + 0x14, "PointerToRawData", "byte/file-offset"),
            characteristics: c.u32f(off + 0x24, "Characteristics", "u32/bitflags"),
        });
    }

    // data directory：范围逐项保留；越界仅产生 diagnostic，不丢弃目录
    let ndd = facts.opt.number_of_rva_and_sizes.value.unwrap_or(16).min(16) as usize;
    let dd0 = oh + 0x70;
    for i in 0..ndd {
        let rva = c.u32f(dd0 + i * 8, "VirtualAddress", "rva32");
        let size = c.u32f(dd0 + i * 8 + 4, "Size", "byte/va-extent");
        if let (Some(r), Some(s), Some(soi)) = (rva.value, size.value, facts.opt.size_of_image.value) {
            if s > 0 && (r >= soi || r.checked_add(s).map_or(true, |e| e > soi)) {
                c.diag.push(Diagnostic {
                    code: "PE_DIRECTORY_OUT_OF_IMAGE".into(),
                    severity: "error".into(),
                    message: format!("data directory {} [RVA 0x{:08X}, +0x{:X}) 超出 SizeOfImage 0x{:08X}",
                                     known_dir_name(i), r, s, soi),
                    span: Some(Span::file(dd0 + i * 8, 8)),
                });
            }
        }
        facts.directories.push(DataDirectoryFact {
            ordinal: i, known_name: known_dir_name(i), rva, size,
        });
    }

    let soi = facts.opt.size_of_image.value;
    let dir_rva = |i: usize| facts.directories.get(i).and_then(|d| d.rva.value);
    let dir_size = |i: usize| facts.directories.get(i).and_then(|d| d.size.value);

    // ---- 重定位 block / entry ----
    if let (Some(mut rva), Some(total)) = (dir_rva(DIR_BASERELOC), dir_size(DIR_BASERELOC)) {
        let mut consumed: u32 = 0;
        let mut bi = 0usize;
        while consumed + 8 <= total {
            let page = match read_u32_via_raw_strict(b, rva, &facts.sections) {
                Some(v) => v,
                None => {
                    c.diag.push(Diagnostic { code: "PE_RELOC_BLOCK_UNREADABLE".into(), severity: "error".into(),
                        message: format!("reloc block 头 page RVA @ RVA 0x{:08X} 无法从 raw 读取", rva), span: None });
                    break;
                }
            };
            let bsize = match read_u32_via_raw_strict(b, rva + 4, &facts.sections) {
                Some(v) => v, None => break,
            };
            if bsize < 8 {
                c.diag.push(Diagnostic { code: "PE_RELOC_BLOCK_BAD_SIZE".into(), severity: "error".into(),
                    message: format!("reloc block @ RVA 0x{:08X} SizeOfBlock=0x{:X} 小于 8", rva, bsize), span: None });
                break;
            }
            let n = ((bsize - 8) / 2) as usize;
            let mut entries = Vec::new();
            let mut ei = 0usize;
            for k in 0..n {
                let slot_rva = rva + 8 + (k as u32) * 2;
                let raw16 = match read_u16_via_raw_strict(b, slot_rva, &facts.sections) {
                    Some(v) => v, None => {
                        c.diag.push(Diagnostic { code: "PE_RELOC_ENTRY_UNREADABLE".into(), severity: "error".into(),
                            message: format!("reloc entry @ RVA 0x{:08X} 无法从 raw 读取", slot_rva), span: None });
                        continue;
                    }
                };
                let ty = (raw16 >> 12) as u8;
                let offp = raw16 & 0x0FFF;
                let (name, width) = reloc_type(ty);
                let target = page.checked_add(offp as u32);
                if let Some(t) = target {
                    if soi.map_or(false, |s| t >= s) {
                        c.diag.push(Diagnostic { code: "PE_RELOC_TARGET_OUT_OF_IMAGE".into(), severity: "error".into(),
                            message: format!("reloc entry 目标 RVA 0x{:08X} 超出 SizeOfImage", t), span: None });
                    }
                }
                entries.push(RelocEntry {
                    index: ei, type_name: name.into(), type_raw: ty, offset_in_page: offp,
                    rva: target.unwrap_or(u32::MAX), width_bytes: width,
                });
                ei += 1;
            }
            facts.reloc_blocks.push(RelocBlock { index: bi, page_rva: page, block_size: bsize, entries });
            bi += 1;
            rva += bsize;
            consumed += bsize;
        }
    }

    // ---- import 描述符与 thunk ----
    if let (Some(mut desc_rva), Some(total)) = (dir_rva(DIR_IMPORT), dir_size(DIR_IMPORT)) {
        let mut di = 0usize;
        loop {
            let oft = read_u32_via_raw_strict(b, desc_rva + 0, &facts.sections);
            let name_rva = read_u32_via_raw_strict(b, desc_rva + 12, &facts.sections);
            let ft = read_u32_via_raw_strict(b, desc_rva + 16, &facts.sections);
            let iat_hint = read_u32_via_raw_strict(b, desc_rva + 20, &facts.sections).unwrap_or(0);
            if desc_rva.checked_sub(dir_rva(DIR_IMPORT).unwrap()).map_or(true, |d| d >= total) {
                break;
            }
            let all_zero = oft.unwrap_or(0) == 0 && name_rva.unwrap_or(0) == 0 && ft.unwrap_or(0) == 0;
            if all_zero { break; }
            let dll = name_rva.and_then(|r| cstring_at(b, r, &facts.sections)).unwrap_or_else(|| {
                c.diag.push(Diagnostic { code: "PE_IMPORT_DLL_NAME_UNREADABLE".into(), severity: "error".into(),
                    message: format!("import 描述符 #{} DLL 名称 @ RVA {:?} 无法读取", di, name_rva), span: None });
                "<unreadable>".into()
            });
            let mut thunks = Vec::new();
            let walk = oft.or(ft);
            if let Some(mut slot) = walk {
                let mut ti = 0usize;
                loop {
                    let val = read_u64_via_raw(b, slot, &facts.sections);
                    match val {
                        None | Some(0) => break,
                        Some(v) => {
                            let ilt_slot_rva = slot;
                            let iat_slot_rva = ft.map(|f| f + (ti as u32) * 8).unwrap_or(slot);
                            let is_ordinal = v & (1u64 << 63) != 0;
                            let (ordinal, hint, name, hn_rva) = if is_ordinal {
                                (Some((v & 0xFFFF) as u16), None, None, None)
                            } else {
                                let hnrva = v as u32;
                                let hint = read_u16_via_raw_strict(b, hnrva, &facts.sections);
                                let nm = cstring_at(b, hnrva + 2, &facts.sections);
                                (None, hint, nm, Some(hnrva))
                            };
                            thunks.push(ImportThunk {
                                index: ti, ilt_slot_rva, iat_slot_rva,
                                is_ordinal, ordinal, hint, name, hint_name_rva: hn_rva,
                            });
                            ti += 1;
                            slot += 8;
                        }
                    }
                }
            }
            facts.imports.push(ImportDescriptor {
                index: di, dll_name: dll,
                original_first_thunk_rva: oft.unwrap_or(0),
                first_thunk_rva: ft.unwrap_or(0),
                iat_size_hint: iat_hint,
                thunks,
            });
            di += 1;
            desc_rva += 20;
        }
    }

    facts.diagnostics = c.diag;
    facts
}

fn read_u32_via_raw_strict(b: &[u8], rva: u32, sections: &[SectionHeader]) -> Option<u32> {
    for s in sections {
        let va = s.virtual_address.value?;
        let vs = s.virtual_size.value?;
        let rp = s.pointer_to_raw_data.value?;
        let rs = s.size_of_raw_data.value?;
        if rva >= va && rva < va + vs {
            let d = rva - va;
            if d + 4 <= rs {
                let start = rp as usize + d as usize;
                return Some(u32::from_le_bytes(b[start..start + 4].try_into().ok()?));
            }
        }
    }
    None
}

fn read_u16_via_raw_strict(b: &[u8], rva: u32, sections: &[SectionHeader]) -> Option<u16> {
    for s in sections {
        let va = s.virtual_address.value?;
        let vs = s.virtual_size.value?;
        let rp = s.pointer_to_raw_data.value?;
        let rs = s.size_of_raw_data.value?;
        if rva >= va && rva < va + vs {
            let d = rva - va;
            if d + 2 <= rs {
                let start = rp as usize + d as usize;
                return Some(u16::from_le_bytes(b[start..start + 2].try_into().ok()?));
            }
        }
    }
    None
}
