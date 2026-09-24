//! 离线案例包：专门针对“PE 装载镜：节映射、base relocation 与 import 解析证据台”。
//!
//! 这不是通用表格：下面手工构造一个 PE32 字节镜像，刻意包含
//!   - 节虚拟范围重叠（.rdata vs .ovr）
//!   - virtual size 大于 raw size（.rdata 映射到 0x2800..0x4000 的零填充）
//!   - 重定位（IMAGE_REL_BASED_HIGHLOW）与修订 image base 后的 32 位溢出
//!   - ordinal import（DEMOLIB.DLL #7）
//!   - 按名 import（DEMOLIB!FuncByName）
//!   - forwarded export（FORWARD!Ghost -> DEMOLIB!FuncByName）
//!   - 缺失 DLL（ABSENT.DLL 无快照）与快照撤除（MISSING.DLL 局部源修订）
//!   - 损坏 directory 范围（export dir 超出 SizeOfImage；debug dir 仅零填充重叠区）
//!
//! 所有布局量都在本文件内以 byte 坐标常量给出，方便审阅者对照。

use crate::types::{DllExport, DllSnapshot, IngestionInput};

pub const FILE_ALIGN: u32 = 0x200;
pub const SECT_ALIGN: u32 = 0x1000;
pub const SIZE_OF_HEADERS: u32 = 0x200;
pub const SIZE_OF_IMAGE: u32 = 0x4000;
pub const ORIGINAL_IMAGE_BASE: u64 = 0x0040_0000;
pub const REVISED_IMAGE_BASE_RAW: &str = "0xFFFF0000";

/// 节布局（raw/virtual 范围，单位 byte）。
/// `.rdata` 虚拟范围覆盖到 0x4000，与 `.ovr` 的虚拟范围 0x3000..0x4000 重叠；
/// `.rdata` raw 只支撑 0x2000..0x2800，其余是装载期零填充。
pub const SECTIONS: &[SectionSpec] = &[
    SectionSpec { name: ".text",  vaddr: 0x1000, vsize: 0x1000, rawptr: 0x0200, rawsize: 0x0200, fill: 0xCC },
    SectionSpec { name: ".rdata", vaddr: 0x2000, vsize: 0x2000, rawptr: 0x0400, rawsize: 0x0800, fill: 0x00 },
    SectionSpec { name: ".ovr",   vaddr: 0x3000, vsize: 0x1000, rawptr: 0x0C00, rawsize: 0x0400, fill: 0xBB },
];

pub struct SectionSpec {
    pub name: &'static str,
    pub vaddr: u32,
    pub vsize: u32,
    pub rawptr: u32,
    pub rawsize: u32,
    pub fill: u8,
}

// .rdata 内的数据目录与对象坐标。
pub const IMPORT_DIR_RVA: u32 = 0x2000;
pub const RELOC_DIR_RVA: u32 = 0x2080;
pub const RELOC_DIR_SIZE: u32 = 0x14; // 2 blocks * 10 bytes
pub const IAT_DIR_RVA: u32 = 0x3800;
pub const DEBUG_DIR_RVA: u32 = 0x3F00;
pub const EXPORT_DIR_RVA_BAD: u32 = 0x4200; // 超出 SizeOfImage：损坏范围。

pub const DLL_NAME_RVAS: &[u32] = &[0x2100, 0x210C, 0x2118, 0x2124];
pub const ILT_RVAS: &[u32] = &[0x2140, 0x2150, 0x2160, 0x2170];
pub const IAT_RVAS: &[u32] = &[0x3800, 0x3810, 0x3820, 0x3830];
pub const HINT_NAME_RVAS: &[u32] = &[0x2180, 0x2190, 0x21A0];

fn u16le(buf: &mut [u8], at: usize, v: u16) { buf[at..at + 2].copy_from_slice(&v.to_le_bytes()); }
fn u32le(buf: &mut [u8], at: usize, v: u32) { buf[at..at + 4].copy_from_slice(&v.to_le_bytes()); }
fn u64le(buf: &mut [u8], at: usize, v: u64) { buf[at..at + 8].copy_from_slice(&v.to_le_bytes()); }

fn put_strz(buf: &mut [u8], at: usize, s: &str) {
    let b = s.as_bytes();
    buf[at..at + b.len()].copy_from_slice(b);
    buf[at + b.len()] = 0;
}

/// 构造固定案例的完整输入：PE 字节 + 预期 image base + DLL export 快照。
pub fn build_ingestion() -> IngestionInput {
    let pe = build_pe();
    IngestionInput {
        expected_image_base: Some(ORIGINAL_IMAGE_BASE),
        pe_bytes_b64: base64::engine::general_purpose::STANDARD.encode(&pe),
        dll_snapshots: vec![
            DllSnapshot {
                dll_name: "DEMOLIB.DLL".into(),
                source_label: "vendor-sdk-2026-09@demolib".into(),
                exports: vec![
                    DllExport { name: Some("FuncByName".into()), ordinal_raw: "3".into(), rva: Some(0x1010), forwarder: None },
                    DllExport { name: Some("Helper".into()),     ordinal_raw: "7".into(), rva: Some(0x1040), forwarder: None },
                ],
            },
            DllSnapshot {
                dll_name: "FORWARD.DLL".into(),
                source_label: "vendor-sdk-2026-09@forward".into(),
                exports: vec![
                    DllExport { name: Some("Ghost".into()), ordinal_raw: "1".into(), rva: None,
                        forwarder: Some("DEMOLIB.FuncByName".into()) },
                ],
            },
            DllSnapshot {
                dll_name: "MISSING.DLL".into(),
                source_label: "leaked-headers@missing".into(),
                exports: vec![
                    DllExport { name: Some("Phantom".into()), ordinal_raw: "1".into(), rva: Some(0x2010), forwarder: None },
                ],
            },
        ],
    }
}

/// 源修订：撤除 MISSING.DLL 快照（只影响 Phantom 这一条局部依赖）。
pub fn missing_dll_removed_label() -> String { "WITHDRAWN:leaked-headers@missing".into() }

/// 手工拼出 PE32 字节。返回的字节布局见本文件顶部常量注释。
pub fn build_pe() -> Vec<u8> {
    let file_size = (SECTIONS.last().unwrap().rawptr + SECTIONS.last().unwrap().rawsize) as usize;
    let mut b = vec![0u8; file_size];

    // ---- DOS header ----
    b[0] = b'M';
    b[1] = b'Z';
    u32le(&mut b, 0x3C, 0x80); // e_lfanew
    // DOS stub 留空（全零）。

    // ---- NT signatures / COFF / optional header ----
    let pe: usize = 0x80;
    b[pe..pe + 4].copy_from_slice(b"PE\0\0");
    let coff = pe + 4;
    u16le(&mut b, coff + 0x00, 0x014C); // Machine: i386
    u16le(&mut b, coff + 0x02, SECTIONS.len() as u16);
    u32le(&mut b, coff + 0x04, 0x6701_0302); // TimeDateStamp（确定性伪值）
    u16le(&mut b, coff + 0x10, 0xE0); // SizeOfOptionalHeader
    u16le(&mut b, coff + 0x12, 0x0102); // Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE

    let opt = coff + 20;
    u16le(&mut b, opt + 0x00, 0x010B); // Magic PE32
    b[opt + 0x02] = 4; // MajorLinkerVersion
    b[opt + 0x03] = 9;
    u32le(&mut b, opt + 0x04, 0x200); // SizeOfCode
    u32le(&mut b, opt + 0x08, 0x800); // SizeOfInitializedData
    u32le(&mut b, opt + 0x0C, 0); // SizeOfUninitializedData
    u32le(&mut b, opt + 0x10, 0x1000); // AddressOfEntryPoint
    u32le(&mut b, opt + 0x14, 0x1000); // BaseOfCode
    u32le(&mut b, opt + 0x18, 0x2000); // BaseOfData
    u32le(&mut b, opt + 0x1C, ORIGINAL_IMAGE_BASE as u32);
    u32le(&mut b, opt + 0x20, SECT_ALIGN);
    u32le(&mut b, opt + 0x24, FILE_ALIGN);
    u16le(&mut b, opt + 0x28, 6); // MajorOperatingSystemVersion
    u16le(&mut b, opt + 0x2A, 0);
    u16le(&mut b, opt + 0x2C, 0); // MajorImageVersion
    u16le(&mut b, opt + 0x2E, 0);
    u16le(&mut b, opt + 0x30, 6); // MajorSubsystemVersion
    u16le(&mut b, opt + 0x32, 0);
    u32le(&mut b, opt + 0x38, 0x1000); // Win32VersionValue
    u32le(&mut b, opt + 0x3C, SIZE_OF_IMAGE);
    u32le(&mut b, opt + 0x40, SIZE_OF_HEADERS);
    u32le(&mut b, opt + 0x44, 0); // CheckSum
    u16le(&mut b, opt + 0x48, 3); // Subsystem CONSOLE
    u16le(&mut b, opt + 0x4A, 0); // DllCharacteristics
    u32le(&mut b, opt + 0x4C, 0x100000); // SizeOfStackReserve
    u32le(&mut b, opt + 0x50, 0x1000); // SizeOfStackCommit
    u32le(&mut b, opt + 0x54, 0x100000); // SizeOfHeapReserve
    u32le(&mut b, opt + 0x58, 0x1000); // SizeOfHeapCommit
    u32le(&mut b, opt + 0x5C, 0); // LoaderFlags
    u32le(&mut b, opt + 0x60, 16); // NumberOfRvaAndSizes

    // Data directory（PE32 每项 8 字节）。
    let dir = opt + 0x64;
    // 0 EXPORT：损坏范围（超出镜像）。
    u32le(&mut b, dir + 8 * 0 + 0, EXPORT_DIR_RVA_BAD);
    u32le(&mut b, dir + 8 * 0 + 4, 0x28);
    // 1 IMPORT。
    u32le(&mut b, dir + 8 * 1 + 0, IMPORT_DIR_RVA);
    u32le(&mut b, dir + 8 * 1 + 4, 4 * 20);
    // 2 RESOURCE：无。
    // 3 EXCEPTION：无。
    // 5 BASERELOC。
    u32le(&mut b, dir + 8 * 5 + 0, RELOC_DIR_RVA);
    u32le(&mut b, dir + 8 * 5 + 4, RELOC_DIR_SIZE);
    // 6 DEBUG：指向仅零填充的重叠区。
    u32le(&mut b, dir + 8 * 6 + 0, DEBUG_DIR_RVA);
    u32le(&mut b, dir + 8 * 6 + 4, 0x1C);
    // 12 IAT：指向 .rdata 零填充与 .ovr 的重叠区。
    u32le(&mut b, dir + 8 * 12 + 0, IAT_DIR_RVA);
    u32le(&mut b, dir + 8 * 12 + 4, 0x40);

    // ---- Section headers（COFF 后、可选头之后）----
    let mut sh = opt + 0xE0;
    for s in SECTIONS {
        let nb = s.name.as_bytes();
        b[sh..sh + nb.len()].copy_from_slice(nb);
        u32le(&mut b, sh + 8, s.vsize);
        u32le(&mut b, sh + 12, s.vaddr);
        u32le(&mut b, sh + 16, s.rawsize);
        u32le(&mut b, sh + 20, s.rawptr);
        u32le(&mut b, sh + 36, 0xC000_0040); // IMAGE_SCN_MEM_READ|EXECUTE/WRITE 由名定，这里统一 READ
        b[sh + 36] = 0x40;
        b[sh + 37] = 0x00;
        b[sh + 38] = 0x00;
        b[sh + 39] = 0xC0;
        sh += 40;
    }

    // ---- 节 raw 区域填充（文件视角）----
    for s in SECTIONS {
        for i in 0..s.rawsize as usize {
            b[s.rawptr as usize + i] = s.fill;
        }
    }

    // .rdata 是数据目录承载节（fill=0），以下按 RVA 写对象。
    let rd = |rva: u32| -> usize {
        let spec = &SECTIONS[1];
        (spec.rawptr + (rva - spec.vaddr)) as usize
    };

    // ---- Import descriptor 数组：4 项（最后一项全零终止）----
    // (ilt, name, iat) per DLL：DEMOLIB / FORWARD / MISSING / ABSENT
    let desc = IMPORT_DIR_RVA as usize;
    for (i, &(ilt, name_rva, iat)) in [
        (ILT_RVAS[0], DLL_NAME_RVAS[0], IAT_RVAS[0]),
        (ILT_RVAS[1], DLL_NAME_RVAS[1], IAT_RVAS[1]),
        (ILT_RVAS[2], DLL_NAME_RVAS[2], IAT_RVAS[2]),
        (ILT_RVAS[3], DLL_NAME_RVAS[3], IAT_RVAS[3]),
    ].iter().enumerate() {
        let d = desc + i * 20;
        u32le(&mut b, d + 0, ilt); // OriginalFirstThunk (ILT)
        u32le(&mut b, d + 12, name_rva); // Name
        u32le(&mut b, d + 16, iat); // FirstThunk (IAT)
    }

    // ---- DLL 名字 ----
    for (&rva, name) in DLL_NAME_RVAS.iter().zip(
        ["DEMOLIB.DLL", "FORWARD.DLL", "MISSING.DLL", "ABSENT.DLL"].iter()) {
        put_strz(&mut b, rd(rva), name);
    }

    // ---- Hint/Name 表 ----
    // FuncByName（DEMOLIB）、Ghost（FORWARD 转发）、Phantom（MISSING）
    put_strz(&mut b, rd(HINT_NAME_RVAS[0]) + 2, "FuncByName");
    put_strz(&mut b, rd(HINT_NAME_RVAS[1]) + 2, "Ghost");
    put_strz(&mut b, rd(HINT_NAME_RVAS[2]) + 2, "Phantom");

    // ---- ILT（PE32：32 位 thunk；0x80000000 位表示 ordinal）----
    let ord_flag: u32 = 0x8000_0000;
    // DEMOLIB：ordinal #7 + 按名 FuncByName
    u32le(&mut b, rd(ILT_RVAS[0]) + 0, ord_flag | 7);
    u32le(&mut b, rd(ILT_RVAS[0]) + 4, HINT_NAME_RVAS[0]);
    // FORWARD：按名 Ghost（快照中是 forwarded export）
    u32le(&mut b, rd(ILT_RVAS[1]) + 0, HINT_NAME_RVAS[1]);
    // MISSING：按名 Phantom（初始快照存在，随后被源修订撤除）
    u32le(&mut b, rd(ILT_RVAS[2]) + 0, HINT_NAME_RVAS[2]);
    // ABSENT：无任何快照（缺 DLL）
    u32le(&mut b, rd(ILT_RVAS[3]) + 0, ord_flag | 1);

    // IAT 位于重叠+零填充区：文件中 .rdata raw 不支撑它，保持零，
    // 由节映射多候选（.rdata 零填充 vs .ovr 内存）在派生层表达，不强行选一。

    // ---- Base relocation：两个 block，各一个 HIGHLOW + 一个 ABSOLUTE 填充 ----
    // block1 页 0x2000：补丁 RVA 0x2198（FuncByName 提示槽，初始 dword = 镜像基址+RVA）
    // block2 页 0x3000：补丁 RVA 0x3800（落在重叠零填充 IAT 区）
    let rdir = RELOC_DIR_RVA as usize;
    let blocks: [(u32, u32); 2] = [(0x2000, 0x2198), (0x3000, 0x3800)];
    for (i, &(page, target)) in blocks.iter().enumerate() {
        let blk = rdir + i * 10;
        u32le(&mut b, blk + 0, page);
        u32le(&mut b, blk + 4, 0x0A); // SizeOfBlock = 8 + 2*1... 取 10（两个 entry，按 WORD 对齐）
        u16le(&mut b, blk + 8, ((3u16) << 12) | ((target - page) as u16)); // type HIGHLOW
        u16le(&mut b, blk + 10, 0); // ABSOLUTE 填充
    }

    // block1 的目标初始值：装载前镜像中应是 original base + RVA（位于 raw 支撑区）。
    u32le(&mut b, rd(0x2198), (ORIGINAL_IMAGE_BASE as u32).wrapping_add(0x2198));

    b
}
