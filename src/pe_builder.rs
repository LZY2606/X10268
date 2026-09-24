//! 固定离线案例 PE 夹具构建器：手工合成一个 PE32+ 映像，
//! 仓库 casepack/ 中的样例字节即由 `build_casepack` 生成，二进制内置同一份内容。
//!
//! 该映像刻意包含全部 7 种装载边界情形：
//!   1. 节重叠：.rdata2 的虚拟区间与 .text 重叠（raw 内容不同 -> 多候选）
//!   2. virtual size > raw size：.text 虚拟尾巴落在 (0x3500,0x4000]，仅零填充候选
//!   3. 重定位溢出：HIGHLOW 类型 32 位补丁在修订 image base 后无符号溢出
//!   4. ordinal import：APILIB #5
//!   5. forwarded export：KERNEL32!GetStdHandle -> NTDLL.RtlGetStdHandle
//!   6. 缺 DLL：MISSING.dll 无导出快照
//!   7. 损坏 data directory 范围：IAT 目录 [0x6000,0x8000) 超出 SizeOfImage 0x7000

pub const IMAGE_BASE: u64 = 0x0040_0000;
pub const SIZE_OF_IMAGE: u32 = 0x7000;
pub const FILE_ALIGN: u32 = 0x200;

pub const SEC_TEXT_VADDR: u32 = 0x1000;
pub const SEC_TEXT_VSIZE: u32 = 0x3000;
pub const SEC_TEXT_RAWPTR: u32 = 0x200;
pub const SEC_TEXT_RAWSIZE: u32 = 0x800;

pub const SEC_RDATA1_VADDR: u32 = 0x2000;
pub const SEC_RDATA1_VSIZE: u32 = 0x1000;
pub const SEC_RDATA1_RAWPTR: u32 = 0xA00;
pub const SEC_RDATA1_RAWSIZE: u32 = 0x600;

pub const SEC_RDATA2_VADDR: u32 = 0x1000;
pub const SEC_RDATA2_VSIZE: u32 = 0x800;
pub const SEC_RDATA2_RAWPTR: u32 = 0x1000;
pub const SEC_RDATA2_RAWSIZE: u32 = 0x400;

pub const SEC_RELOC_VADDR: u32 = 0x6000;
pub const SEC_RELOC_VSIZE: u32 = 0x1000;
pub const SEC_RELOC_RAWPTR: u32 = 0x1400;
pub const SEC_RELOC_RAWSIZE: u32 = 0x38;

pub const IAT_DIR_RVA: u32 = 0x6000;
pub const IAT_DIR_SIZE: u32 = 0x2000;
pub const IMPORT_DIR_RVA: u32 = 0x2400;
pub const IMPORT_DIR_SIZE: u32 = 0x80;

// .rdata1 布局常量（raw == virtual 起点映射）
pub const ILT1_RVA: u32 = 0x2000; // KERNEL32: 名称 + 转发 2 thunk
pub const FT1_RVA: u32 = 0x2010;
pub const ILT2_RVA: u32 = 0x2020; // KERNELBASE: 名称 1 thunk
pub const FT2_RVA: u32 = 0x2028;
pub const ILT3_RVA: u32 = 0x2030; // APILIB: ordinal 1 thunk
pub const FT3_RVA: u32 = 0x2038;
pub const ILT4_RVA: u32 = 0x2040; // MISSING: 名称 1 thunk
pub const FT4_RVA: u32 = 0x2048;

pub const DESC_K32_RVA: u32 = 0x2400;
pub const DESC_KBASE_RVA: u32 = 0x2414;
pub const DESC_APILIB_RVA: u32 = 0x2428;
pub const DESC_MISSING_RVA: u32 = 0x243C;
pub const DESC_NULL_RVA: u32 = 0x2450;

pub const NAME_OPEN_THING_RVA: u32 = 0x2200;
pub const NAME_EXIT_PROCESS_RVA: u32 = 0x2220;
pub const NAME_NOPE_RVA: u32 = 0x2240;
pub const DLL_K32_RVA: u32 = 0x2300;
pub const DLL_KBASE_RVA: u32 = 0x2310;
pub const DLL_APILIB_RVA: u32 = 0x2320;
pub const DLL_MISSING_RVA: u32 = 0x2330;

// 重定位补丁位
pub const RELOC_RDATA1_IA: u32 = 0x2008; // DIR64，命中 .rdata1 名称槽
pub const RELOC_ZEROFILL: u32 = 0x3500; // HIGHLOW，.text 虚拟零填充区
pub const RELOC_UNMAPPED: u32 = 0x5100; // HIGHLOW，任何节都不覆盖
pub const RELOC_OVERLAP: u32 = 0x1004; // HIGHLOW，.text 与 .rdata2 重叠

fn u16(v: u16) -> [u8; 2] { v.to_le_bytes() }
fn u32b(v: u32) -> [u8; 4] { v.to_le_bytes() }
fn u64b(v: u64) -> [u8; 8] { v.to_le_bytes() }

fn put(buf: &mut Vec<u8>, off: usize, bytes: &[u8]) {
    if buf.len() < off + bytes.len() {
        buf.resize(off + bytes.len(), 0);
    }
    buf[off..off + bytes.len()].copy_from_slice(bytes);
}
fn put_u16(buf: &mut Vec<u8>, off: usize, v: u16) { put(buf, off, &u16(v)); }
fn put_u32(buf: &mut Vec<u8>, off: usize, v: u32) { put(buf, off, &u32b(v)); }
fn put_u64(buf: &mut Vec<u8>, off: usize, v: u64) { put(buf, off, &u64b(v)); }

fn cstr(buf: &mut Vec<u8>, off: usize, s: &str) {
    put(buf, off, s.as_bytes());
    put(buf, off + s.len(), &[0]);
}

fn section_header(buf: &mut Vec<u8>, off: usize, name: &[u8; 8],
                  vsize: u32, vaddr: u32, rawsize: u32, rawptr: u32, chars: u32) {
    put(buf, off, name);
    put_u32(buf, off + 0x08, vsize);
    put_u32(buf, off + 0x0C, vaddr);
    put_u32(buf, off + 0x10, rawsize);
    put_u32(buf, off + 0x14, rawptr);
    // 0x18..0x24: pointer to relocations/line numbers/numbers = 0
    put_u32(buf, off + 0x24, chars);
}

/// 构建固定案例的 PE 字节（PE32+，小端）。
pub fn build_pe() -> Vec<u8> {
    let mut b = vec![0u8; SEC_RELOC_RAWPTR as usize + SEC_RELOC_RAWSIZE as usize];

    // ---- DOS header（MZ 与 e_lfanew，中间保留原始占位字节）----
    b[0] = b'M';
    b[1] = b'Z';
    for (i, x) in b[0x02..0x3C].iter_mut().enumerate() {
        *x = (i as u8).wrapping_mul(7).wrapping_add(0x11);
    }
    put_u32(&mut b, 0x3C, 0x80); // e_lfanew
    // DOS stub
    cstr(&mut b, 0x40, "This program cannot be run in DOS mode.");

    // ---- NT headers @0x80 ----
    let nt = 0x80;
    put(&mut b, nt, b"PE\0\0");
    // COFF file header @0x84
    put_u16(&mut b, nt + 4, 0x8664); // IMAGE_FILE_MACHINE_AMD64
    put_u16(&mut b, nt + 6, 4); // NumberOfSections
    put_u32(&mut b, nt + 8, 0x5F5E100); // TimeDateStamp（保留原值）
    put_u32(&mut b, nt + 12, 0); // PointerToSymbolTable
    put_u32(&mut b, nt + 16, 0); // NumberOfSymbols
    put_u16(&mut b, nt + 20, 0xF0); // SizeOfOptionalHeader
    put_u16(&mut b, nt + 22, 0x0022); // Characteristics: EXECUTABLE_IMAGE | DLL

    // ---- Optional header (PE32+) @0x98 ----
    let oh = nt + 24;
    put_u16(&mut b, oh + 0x00, 0x020B); // PE32+
    b[oh + 0x02] = 14; // MajorLinkerVersion
    b[oh + 0x03] = 0; // MinorLinkerVersion
    put_u32(&mut b, oh + 0x04, SEC_TEXT_RAWSIZE); // SizeOfCode
    put_u32(&mut b, oh + 0x08, SEC_RDATA1_RAWSIZE + SEC_RDATA2_RAWSIZE); // SizeOfInitializedData
    put_u32(&mut b, oh + 0x0C, 0); // SizeOfUninitializedData
    put_u32(&mut b, oh + 0x10, 0x1010); // AddressOfEntryPoint
    put_u32(&mut b, oh + 0x14, SEC_TEXT_VADDR); // BaseOfCode
    put_u64(&mut b, oh + 0x18, IMAGE_BASE);
    put_u32(&mut b, oh + 0x20, FILE_ALIGN); // SectionAlignment
    put_u32(&mut b, oh + 0x24, FILE_ALIGN); // FileAlignment
    put_u16(&mut b, oh + 0x28, 6); // MajorOperatingSystemVersion
    put_u16(&mut b, oh + 0x2A, 2);
    put_u16(&mut b, oh + 0x2C, 0); // ImageVersion
    put_u16(&mut b, oh + 0x2E, 0);
    put_u16(&mut b, oh + 0x30, 6); // SubsystemVersion
    put_u16(&mut b, oh + 0x32, 2);
    put_u32(&mut b, oh + 0x34, 0); // Win32VersionValue
    put_u32(&mut b, oh + 0x38, SIZE_OF_IMAGE);
    put_u32(&mut b, oh + 0x3C, 0x200); // SizeOfHeaders
    put_u16(&mut b, oh + 0x40, 0); // CheckSum
    put_u16(&mut b, oh + 0x42, 3); // Subsystem: CONSOLE
    put_u16(&mut b, oh + 0x44, 0x0160); // DllCharacteristics: DYNAMIC_BASE|NX_COMPAT
    put_u64(&mut b, oh + 0x48, 0x100000); // SizeOfStackReserve
    put_u64(&mut b, oh + 0x50, 0x1000); // SizeOfStackCommit
    put_u64(&mut b, oh + 0x58, 0x100000); // SizeOfHeapReserve
    put_u64(&mut b, oh + 0x60, 0x1000); // SizeOfHeapCommit
    put_u32(&mut b, oh + 0x68, 0); // LoaderFlags
    put_u32(&mut b, oh + 0x6C, 16); // NumberOfRvaAndSizes

    // data directories @ oh+0x70（16 项，每项 8 字节）
    let dd = oh + 0x70;
    put_u32(&mut b, dd + 0x00, 0); // Export
    put_u32(&mut b, dd + 0x04, 0);
    put_u32(&mut b, dd + 0x08, IMPORT_DIR_RVA); // Import
    put_u32(&mut b, dd + 0x0C, IMPORT_DIR_SIZE);
    put_u32(&mut b, dd + 0x10, SEC_RELOC_VADDR); // BaseReloc
    put_u32(&mut b, dd + 0x14, 0x38);
    put_u32(&mut b, dd + 0x18, IAT_DIR_RVA); // IAT —— 故意越界（损坏目录范围）
    put_u32(&mut b, dd + 0x1C, IAT_DIR_SIZE);

    // ---- section table @0x108 ----
    section_header(&mut b, 0x108, b".text\0\0\0", SEC_TEXT_VSIZE, SEC_TEXT_VADDR,
                   SEC_TEXT_RAWSIZE, SEC_TEXT_RAWPTR, 0x60000020);
    section_header(&mut b, 0x120, b".rdata1\0", SEC_RDATA1_VSIZE, SEC_RDATA1_VADDR,
                   SEC_RDATA1_RAWSIZE, SEC_RDATA1_RAWPTR, 0x40000040);
    section_header(&mut b, 0x138, b".rdata2\0", SEC_RDATA2_VSIZE, SEC_RDATA2_VADDR,
                   SEC_RDATA2_RAWSIZE, SEC_RDATA2_RAWPTR, 0x40000040);
    section_header(&mut b, 0x150, b".reloc\0\0", SEC_RELOC_VSIZE, SEC_RELOC_VADDR,
                   SEC_RELOC_RAWSIZE, SEC_RELOC_RAWPTR, 0x42000040);

    // ---- .text raw [0x200,0xA00)：代码外观字节；[0x3500,0x4000] 无 raw（仅零填充）----
    for i in 0..SEC_TEXT_RAWSIZE as usize {
        b[SEC_TEXT_RAWPTR as usize + i] = 0xC3u8.wrapping_add((i % 5) as u8);
    }
    put_u32(&mut b, SEC_TEXT_RAWPTR as usize + 0x004, 0x0000_0000); // 重叠点原始 4 字节

    // ---- .rdata2 raw [0x1000,0x1400)：虚拟区间与 .text 重叠，字节不同 ----
    for i in 0..SEC_RDATA2_RAWSIZE as usize {
        b[SEC_RDATA2_RAWPTR as usize + i] = 0xB2u8.wrapping_add((i % 3) as u8);
    }


    // ---- .rdata1 raw [0xA00,0x1000)：先铺可辨识底字节，再写导入结构 ----
    let r1 = SEC_RDATA1_RAWPTR as usize;
    for i in 0..SEC_RDATA1_RAWSIZE as usize {
        b[r1 + i] = 0xAA;
    }
    // ILT / FT：u64 槽
    put_u64(&mut b, r1 + 0x000, NAME_EXIT_PROCESS_RVA as u64); // ILT1[0]
    put_u64(&mut b, r1 + 0x008, NAME_EXIT_PROCESS_RVA as u64); // ILT1[1]（转发导出）
    put_u64(&mut b, r1 + 0x010, NAME_EXIT_PROCESS_RVA as u64); // FT1[0]
    put_u64(&mut b, r1 + 0x018, NAME_EXIT_PROCESS_RVA as u64); // FT1[1]
    put_u64(&mut b, r1 + 0x020, NAME_OPEN_THING_RVA as u64); // ILT2[0]
    put_u64(&mut b, r1 + 0x028, NAME_OPEN_THING_RVA as u64); // FT2[0]
    put_u64(&mut b, r1 + 0x030, 0x8000_0000_0000_0005); // ILT3[0] ordinal 5
    put_u64(&mut b, r1 + 0x038, 0x8000_0000_0000_0005); // FT3[0]
    put_u64(&mut b, r1 + 0x040, NAME_NOPE_RVA as u64); // ILT4[0]
    put_u64(&mut b, r1 + 0x048, NAME_NOPE_RVA as u64); // FT4[0]

    let desc = |rva: u32| -> usize { r1 + (rva - SEC_RDATA1_VADDR) as usize };
    let write_desc = |b: &mut Vec<u8>, at: usize, ilt: u32, dll: u32, ft: u32| {
        put_u32(b, at + 0x00, ilt);
        // OriginalFirstThunk/TimeDateStamp/ForwarderChain 其余字段保持 0
        put_u32(b, at + 0x0C, dll);
        put_u32(b, at + 0x10, ft);
        put_u32(b, at + 0x14, 0x10);
    };
    write_desc(&mut b, desc(DESC_K32_RVA), ILT1_RVA, DLL_K32_RVA, FT1_RVA);
    write_desc(&mut b, desc(DESC_KBASE_RVA), ILT2_RVA, DLL_KBASE_RVA, FT2_RVA);
    write_desc(&mut b, desc(DESC_APILIB_RVA), ILT3_RVA, DLL_APILIB_RVA, FT3_RVA);
    write_desc(&mut b, desc(DESC_MISSING_RVA), ILT4_RVA, DLL_MISSING_RVA, FT4_RVA);

    let name_at = |rva: u32| -> usize { r1 + (rva - SEC_RDATA1_VADDR) as usize };
    let hint_name = |b: &mut Vec<u8>, at: usize, hint: u16, n: &str| {
        put_u16(b, at, hint);
        cstr(b, at + 2, n);
    };
    hint_name(&mut b, name_at(NAME_OPEN_THING_RVA), 1, "OpenThing");
    hint_name(&mut b, name_at(NAME_EXIT_PROCESS_RVA), 2, "ExitProcess");
    hint_name(&mut b, name_at(NAME_NOPE_RVA), 3, "Nope");
    cstr(&mut b, name_at(DLL_K32_RVA), "KERNEL32.dll");
    cstr(&mut b, name_at(DLL_KBASE_RVA), "KERNELBASE.dll");
    cstr(&mut b, name_at(DLL_APILIB_RVA), "APILIB.dll");
    cstr(&mut b, name_at(DLL_MISSING_RVA), "MISSING.dll");

    // ---- .reloc raw [0x1400,0x1428)：两个 block ----
    let rb = SEC_RELOC_RAWPTR as usize;
    // block 1: page 0x1000，DIR64@+0x008, HIGHLOW@+0x004, ABSOLUTE 填充
    put_u32(&mut b, rb + 0x00, 0x1000);
    put_u32(&mut b, rb + 0x04, 0x10); // block 含 3 个 entry（含 ABSOLUTE）
    put_u16(&mut b, rb + 0x08, (0x0A << 12) | 0x008); // IMAGE_REL_BASED_DIR64  -> 0x1008
    put_u16(&mut b, rb + 0x0A, (0x03 << 12) | 0x004); // IMAGE_REL_BASED_HIGHLOW -> 0x1004
    put_u16(&mut b, rb + 0x0C, 0x0000); // ABSOLUTE
    // block 2: page 0x3000，HIGHLOW@+0x500；page 0x5000，HIGHLOW@+0x100
    put_u32(&mut b, rb + 0x10, 0x3000);
    put_u32(&mut b, rb + 0x14, 0x08);
    put_u16(&mut b, rb + 0x18, (0x03 << 12) | 0x500); // -> 0x3500 零填充
    put_u32(&mut b, rb + 0x1C, 0x5000);
    put_u32(&mut b, rb + 0x20, 0x08);
    put_u16(&mut b, rb + 0x24, (0x03 << 12) | 0x100); // -> 0x5100 无映射
    // block 3: page 0x2000，DIR64@+0x008（命中 .rdata1 的 IAT 名称槽，唯一干净映射）
    put_u32(&mut b, rb + 0x28, 0x2000);
    put_u32(&mut b, rb + 0x2C, 0x10);
    put_u16(&mut b, rb + 0x30, (0x0A << 12) | 0x008); // DIR64 -> 0x2008 干净映射
    put_u16(&mut b, rb + 0x32, 0x0000); // ABSOLUTE

    b
}

/// 导出快照 v1：KERNEL32 提供转发导出；KERNELBASE 正常名称导出；APILIB 空导出（ordinal 缺失）。
pub fn exports_v1_json() -> String {
    r#"{
  "format": "dll-export-snapshot",
  "format_version": "1.0",
  "revision": 1,
  "dlls": [
    {
      "name": "KERNEL32.dll",
      "image_base": {"value": "0x76D20000", "unit": "u64-absolute-va"},
      "exports": [
        {"name": "ExitProcess", "ordinal": 2, "rva": {"value": "0x1A3B0", "unit": "rva32"},
         "forwarder": "NTDLL.RtlExitProcess"},
        {"name": "GetStdHandle", "ordinal": 16, "rva": {"value": "0x1A120", "unit": "rva32"},
         "forwarder": "NTDLL.RtlGetStdHandle"}
      ]
    },
    {
      "name": "KERNELBASE.dll",
      "image_base": {"value": "0x75F80000", "unit": "u64-absolute-va"},
      "exports": [
        {"name": "OpenThing", "ordinal": 7, "rva": {"value": "0x43210", "unit": "rva32"}}
      ]
    },
    {
      "name": "APILIB.dll",
      "image_base": {"value": "0x6E010000", "unit": "u64-absolute-va"},
      "exports": []
    }
  ]
}
"#.to_string()
}

/// 导出快照 v2：只新增 APILIB ordinal 5（局部依赖改动），并带一条无法转换的畸形记录。
pub fn exports_v2_json() -> String {
    r#"{
  "format": "dll-export-snapshot",
  "format_version": "1.0",
  "revision": 2,
  "dlls": [
    {
      "name": "KERNEL32.dll",
      "image_base": {"value": "0x76D20000", "unit": "u64-absolute-va"},
      "exports": [
        {"name": "ExitProcess", "ordinal": 2, "rva": {"value": "0x1A3B0", "unit": "rva32"},
         "forwarder": "NTDLL.RtlExitProcess"},
        {"name": "GetStdHandle", "ordinal": 16, "rva": {"value": "0x1A120", "unit": "rva32"},
         "forwarder": "NTDLL.RtlGetStdHandle"}
      ]
    },
    {
      "name": "KERNELBASE.dll",
      "image_base": {"value": "0x75F80000", "unit": "u64-absolute-va"},
      "exports": [
        {"name": "OpenThing",  "ordinal": 7, "rva": {"value": "0x43210", "unit": "rva32"}}
      ]
    },
    {
      "name": "APILIB.dll",
      "image_base": {"value": "0x6E010000", "unit": "u64-absolute-va"},
      "exports": [
        {"ordinal": 5, "rva": {"value": "0x2C0", "unit": "rva32"}, "name": "Helper5"},
        {"ordinal": 9, "rva": {"value": "not-a-number", "unit": "rva32"}, "name": "Broken9"}
      ]
    }
  ]
}
"#.to_string()
}

/// 装载参数 v1：预期 image base 与 PE 头一致。
pub fn params_v1_json() -> String {
    format!(r#"{{
  "format": "loader-params",
  "format_version": "1.0",
  "revision": 1,
  "image_base": {{"value": "0x{:016X}", "unit": "u64-absolute-va"}}
}}
"#, IMAGE_BASE)
}

/// 装载参数 v2：image base 改到 0x100000000，HIGHLOW（32 位）补丁全部溢出；DIR64 正常。
pub fn params_v2_json() -> String {
    r#"{
  "format": "loader-params",
  "format_version": "1.0",
  "revision": 2,
  "image_base": {"value": "0x0000000100000000", "unit": "u64-absolute-va"}
}
"#.to_string()
}
