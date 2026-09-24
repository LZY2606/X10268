//! 仓库自带离线案例包“PE 装载镜：节映射、base relocation 与 import 解析证据台”。
//! 所有字节由确定性构建器生成，不下载任何外部材料。
//!
//! 覆盖固定情形：节重叠、virtual size > raw、重定位溢出、ordinal import、
//! forwarded export、缺 DLL、损坏 data directory 范围。

use serde_json::{json, Value};

pub const CASE_ID: &str = "case-pe-loader-mirror";
pub const CASE_NAME: &str = "PE 装载镜：节映射 / base relocation / import 解析证据台";
pub const PE_ARTIFACT_ID: &str = "art:pe:main.exe";
pub const EXPECTED_BASE: i64 = 0x0000_0001_8000_0000;
pub const HEADER_BASE: i64 = 0x0000_0001_4000_0000;

// 布局常量（全部带 byte/rva 坐标含义）
pub const FILE_ALIGN: usize = 0x200;
pub const SECT_ALIGN: usize = 0x1000;
pub const HEADERS_RAW: usize = 0x400;

// 节：name, vsize, vaddr, rsize, rptr
pub const SECT_TEXT:  (&str, usize, usize, usize, usize) = (".text", 0x1000, 0x1000, 0x600, 0x400);
pub const SECT_RDATA: (&str, usize, usize, usize, usize) = (".rdata", 0x1000, 0x2000, 0x400, 0xA00);
pub const SECT_OVR:   (&str, usize, usize, usize, usize) = (".ovr",   0x800, 0x2800, 0x100, 0xE00); // 与 .rdata 虚拟重叠
pub const SECT_DATA:  (&str, usize, usize, usize, usize) = (".data", 0x1200, 0x3000, 0x400, 0xF00); // virtual > raw
pub const SECT_RELOC: (&str, usize, usize, usize, usize) = (".reloc", 0x200, 0x5000, 0x200, 0x1300);
pub const FILE_LEN: usize = 0x1500;

// RVA 锚点
pub const RDATA_BASE: usize = 0x2000;
pub const IAT_RVA: usize = RDATA_BASE + 0x000;  // 0x2000，槽位 8 字节，DIR64 重定位
pub const ILT_KERNEL_RVA: usize = RDATA_BASE + 0x020;
pub const ILT_USER32_RVA: usize = RDATA_BASE + 0x040;
pub const ILT_GHOST_RVA: usize = RDATA_BASE + 0x060;
pub const DESCR_BASE: usize = RDATA_BASE + 0x100;
pub const NAME_BASE: usize = RDATA_BASE + 0x180;
pub const HINT_BASE: usize = RDATA_BASE + 0x200;
// IAT：kernel32 两个槽（含 ordinal），user32 两个槽，ghostdll 一个槽
pub const IAT_USER32_RVA: usize = IAT_RVA + 16;
pub const IAT_GHOST_RVA: usize = IAT_RVA + 32;

pub const RELOC_DIR_RVA: usize = 0x5000;
pub const RELOC_DIR_SIZE: usize = 0x30;

pub const BAD_RELOC_TARGET_RVA: i64 = 0x6FFC; // 超出 size_of_image

#[derive(Debug, Clone)]
pub struct BuiltPe {
    pub bytes: Vec<u8>,
    pub corrupt_reloc_directory: bool,
}

fn w16(buf: &mut [u8], off: usize, v: u16) { buf[off..off + 2].copy_from_slice(&v.to_le_bytes()); }
fn w32(buf: &mut [u8], off: usize, v: u32) { buf[off..off + 4].copy_from_slice(&v.to_le_bytes()); }
fn w64(buf: &mut [u8], off: usize, v: u64) { buf[off..off + 8].copy_from_slice(&v.to_le_bytes()); }
fn putstr(buf: &mut [u8], off: usize, s: &str) {
    let b = s.as_bytes();
    buf[off..off + b.len()].copy_from_slice(b);
    buf[off + b.len()] = 0;
}

pub fn sections() -> Vec<(&'static str, usize, usize, usize, usize)> {
    vec![SECT_TEXT, SECT_RDATA, SECT_OVR, SECT_DATA, SECT_RELOC]
}

pub fn build_pe() -> BuiltPe {
    let mut buf = vec![0u8; FILE_LEN];

    // DOS header
    w16(&mut buf, 0, 0x5A4D);
    w32(&mut buf, 0x3C, 0x80);
    // NT signature + COFF
    let pe = 0x80usize;
    w32(&mut buf, pe, 0x0000_4550);
    let coff = pe + 4;
    w16(&mut buf, coff, 0x8664);        // AMD64
    w16(&mut buf, coff + 2, 5);         // sections
    w32(&mut buf, coff + 4, 0);         // timestamp
    w32(&mut buf, coff + 16, 0xF0);     // size of optional header
    w16(&mut buf, coff + 18, 0x0022);   // characteristics
    let opt = coff + 20;
    w16(&mut buf, opt, 0x20B);          // PE32+
    buf[opt + 2] = 14;                  // linker major
    w32(&mut buf, opt + 4, SECT_TEXT.3 as u32); // size of code
    w64(&mut buf, opt + 24, HEADER_BASE as u64);
    w32(&mut buf, opt + 32, SECT_ALIGN as u32);
    w32(&mut buf, opt + 36, FILE_ALIGN as u32);
    w32(&mut buf, opt + 56, 0x6000);    // size of image
    w32(&mut buf, opt + 60, HEADERS_RAW as u32);
    w16(&mut buf, opt + 68, 6);         // subsystem? (just populated)
    w32(&mut buf, opt + 108, 16);       // number of data dirs
    let dir = opt + 112;
    // export(0) none, import(1), base_reloc(5), iat(12)
    w32(&mut buf, dir + 1 * 8, DESCR_BASE as u32);
    w32(&mut buf, dir + 1 * 8 + 4, 3 * 20);
    w32(&mut buf, dir + 5 * 8, RELOC_DIR_RVA as u32);
    w32(&mut buf, dir + 5 * 8 + 4, RELOC_DIR_SIZE as u32);
    w32(&mut buf, dir + 12 * 8, IAT_RVA as u32);
    w32(&mut buf, dir + 12 * 8 + 4, 40);

    // section table
    let table = opt + 0xF0;
    for (i, (name, vs, va, rs, rp)) in sections().iter().enumerate() {
        let o = table + i * 40;
        let nb = name.as_bytes();
        buf[o..o + nb.len()].copy_from_slice(nb);
        w32(&mut buf, o + 8, *vs as u32);
        w32(&mut buf, o + 12, *va as u32);
        w32(&mut buf, o + 16, *rs as u32);
        w32(&mut buf, o + 20, *rp as u32);
        w32(&mut buf, o + 36, 0x6000_0020);
    }

    // ---- .rdata 内容：以 RVA 计算文件偏移（.rdata raw ptr 0xA00）----
    let rfo = |rva: usize| SECT_RDATA.4 + (rva - SECT_RDATA.2);

    // 描述符：kernel32 / user32 / ghostdll
    let dlls = [
        ("KERNEL32.dll", ILT_KERNEL_RVA, IAT_RVA, NAME_BASE + 0x00),
        ("USER32.dll",   ILT_USER32_RVA, IAT_USER32_RVA, NAME_BASE + 0x10),
        ("GHOSTDLL.dll", ILT_GHOST_RVA,  IAT_GHOST_RVA,  NAME_BASE + 0x20),
    ];
    for (i, (dll, ilt, iat, name_rva)) in dlls.iter().enumerate() {
        let d = rfo(DESCR_BASE + i * 20);
        w32(&mut buf, d, *ilt as u32);
        w32(&mut buf, d + 12, *name_rva as u32);
        w32(&mut buf, d + 16, *iat as u32);
        putstr(&mut buf, rfo(*name_rva), dll);
    }
    // 字符串：kernel32: CreateFileW(name), Sleep(ordinal)
    // user32: MessageBoxW(forwarded), DefWindowProcW(name)
    putstr(&mut buf, rfo(HINT_BASE + 0x00 + 2), "CreateFileW");
    w16(&mut buf, rfo(HINT_BASE + 0x00), 0x0010);
    putstr(&mut buf, rfo(HINT_BASE + 0x20 + 2), "MessageBoxW");
    w16(&mut buf, rfo(HINT_BASE + 0x20), 0x0010);
    putstr(&mut buf, rfo(HINT_BASE + 0x40 + 2), "DefWindowProcW");
    w16(&mut buf, rfo(HINT_BASE + 0x40), 0x0010);

    // ILT / IAT 数据（ILT 与 IAT 相同；ghostdll 槽初始 0 之后由构建步骤填）
    // kernel32: CreateFileW by name, Sleep by ordinal #1200
    w64(&mut buf, rfo(ILT_KERNEL_RVA), HINT_BASE as u64 + 0x00);
    w64(&mut buf, rfo(ILT_KERNEL_RVA + 8), 0x8000_0000_0000_04B0); // ordinal 1200
    w64(&mut buf, rfo(IAT_RVA), HINT_BASE as u64 + 0x00);
    w64(&mut buf, rfo(IAT_RVA + 8), 0x8000_0000_0000_04B0);
    // user32: MessageBoxW(forwarded), DefWindowProcW
    w64(&mut buf, rfo(ILT_USER32_RVA), HINT_BASE as u64 + 0x20);
    w64(&mut buf, rfo(ILT_USER32_RVA + 8), HINT_BASE as u64 + 0x40);
    w64(&mut buf, rfo(IAT_USER32_RVA), HINT_BASE as u64 + 0x20);
    w64(&mut buf, rfo(IAT_USER32_RVA + 8), HINT_BASE as u64 + 0x40);
    // ghostdll：按名称导入，且无快照（缺 DLL）
    putstr(&mut buf, rfo(HINT_BASE + 0x60 + 2), "GhostStartup");
    w16(&mut buf, rfo(HINT_BASE + 0x60), 0x0001);
    w64(&mut buf, rfo(ILT_GHOST_RVA), HINT_BASE as u64 + 0x60);
    w64(&mut buf, rfo(IAT_GHOST_RVA), HINT_BASE as u64 + 0x60);

    // ---- 重定位块（页 0x2000：覆盖 IAT 前三个 DIR64 槽 + 一个 HIGHLOW 溢出槽）----
    let rlo = SECT_RELOC.4;
    let entries: Vec<(u32, u16)> = vec![
        (0x2000, 10),   // DIR64 -> IAT+0
        (0x2008, 10),   // DIR64 -> IAT+8
        (0x2010, 10),   // DIR64 -> IAT+16
        (0x2020, 3),    // HIGHLOW @ 0x2020：delta 超出 i32，触发 32 位溢出
        (0x6000, 10),   // 页 0x6000 不存在 -> 目标越界（重定位溢出）
    ];
    let mut p = rlo;
    let page = 0x2000u32;
    let block_size = 8 + 4 * 2; // 4 entries on page 0x2000
    w32(&mut buf, p, page);
    w32(&mut buf, p + 4, block_size as u32);
    for (k, (_rva, kind)) in entries.iter().take(4).enumerate() {
        let target = entries[k].0;
        let off = (target - page) as u16;
        w16(&mut buf, p + 8 + k * 2, (kind << 12) | off);
    }
    // 第二个块：页 0x6000（越界）
    let p2 = p + block_size;
    w32(&mut buf, p2, 0x6000);
    w32(&mut buf, p2 + 4, 10); // 8 + 1 entry
    w16(&mut buf, p2 + 8, (10 << 12) | 0x000);

    // 非零标记字节，证明 raw 内容被保留
    buf[SECT_TEXT.4] = 0xC3;
    buf[SECT_OVR.4] = 0xAA;
    buf[SECT_DATA.4] = 0xBB;

    BuiltPe { bytes: buf, corrupt_reloc_directory: false }
}

/// 损坏 directory 范围变体：把 base reloc directory 指向无任何 section 覆盖的 RVA。
pub fn build_pe_corrupt_reloc_directory() -> Vec<u8> {
    let mut b = build_pe().bytes;
    // optional header 中 data directory[5] 在 opt+112+40
    let off = 0x80 + 4 + 20 + 112 + 5 * 8;
    w32(&mut b, off, 0x7000);   // 0x7000 > size_of_image，任何节都不覆盖
    w32(&mut b, off + 4, 0x100);
    b
}

/// 损坏 export 范围变体：快照 JSON 中显式声明 corrupt_range（来源材料保留诊断语义）。
pub fn export_snapshots() -> Vec<Value> {
    vec![
        json!({
            "artifact_id": "art:dll:kernel32.snapshot.json",
            "dll": "KERNEL32.dll",
            "snapshot_revision": 1,
            "exports": [
                {"name": "CreateFileW", "ordinal": 100, "rva": 0x012340, "unit": "rva"},
                {"name": "Sleep", "ordinal": 1200, "rva": 0x015010, "unit": "rva"}
            ]
        }),
        json!({
            "artifact_id": "art:dll:user32.snapshot.json",
            "dll": "USER32.dll",
            "snapshot_revision": 1,
            "exports": [
                {"name": "MessageBoxW", "ordinal": 2104, "rva": 0x022020, "unit": "rva",
                 "forwarder": "ext-ms-win-rtcore-ntuser-dialog-l1-1-0.MessageBoxW"},
                {"name": "DefWindowProcW", "ordinal": 1020, "rva": 0x022100, "unit": "rva"}
            ]
        }),
        json!({
            "artifact_id": "art:dll:msimg.snapshot.json",
            "dll": "MSIMG32.dll",
            "snapshot_revision": 1,
            "corrupt_range": true,
            "export_directory": {"rva": 0x99999, "size": 0x40, "unit": "rva"},
            "exports": []
        }),
    ]
}

/// 规则参数 v1：探针覆盖无映射/重叠/仅零填充。
pub fn rules_v1() -> Value {
    json!({
        "expected_image_base": EXPECTED_BASE,
        "zero_fill_beyond_raw": true,
        "reloc_delta_base": "preferred",
        "reloc_types": {"HIGHLOW": {"width_bits": 32}, "DIR64": {"width_bits": 64}},
        "available_dlls": ["KERNEL32.dll", "USER32.dll"],
        "rva_probes": [
            {"label": "unmapped_gap", "rva": 0x4200, "len_bytes": 8},
            {"label": "overlap_rdata_ovr", "rva": 0x2900, "len_bytes": 8},
            {"label": "zerofill_data_tail", "rva": 0x3F00, "len_bytes": 8},
            {"label": "headers", "rva": 0x100, "len_bytes": 4}
        ]
    })
}

/// 规则参数 v2（一次参数修订）：调整零填充策略说明并新增一个零填充探针。
/// 失效范围仅包含依赖 ruleset 的 rva_resolution / reloc_patch / image_summary。
pub fn rules_v2() -> Value {
    let mut v = rules_v1();
    v["zero_fill_beyond_raw"] = json!(true);
    v["zero_fill_policy"] = json!("loader guarantees zero-filled trailing page remainder");
    v["rva_probes"].as_array_mut().unwrap().push(json!({"label": "zerofill_data_deep", "rva": 0x3FF0, "len_bytes": 8}));
    v
}

/// 一次只影响局部依赖的源数据改动：user32 导出快照修订（仅 DefWindowProcW 的 RVA 改变）。
/// 只应失效 USER32.dll 相关 import_binding，kernel32/ghostdll 不受影响。
pub fn user32_snapshot_v2() -> Value {
    json!({
        "artifact_id": "art:dll:user32.snapshot.json",
        "dll": "USER32.dll",
        "snapshot_revision": 2,
        "exports": [
            {"name": "MessageBoxW", "ordinal": 2104, "rva": 0x022020, "unit": "rva",
             "forwarder": "ext-ms-win-rtcore-ntuser-dialog-l1-1-0.MessageBoxW"},
            {"name": "DefWindowProcW", "ordinal": 1020, "rva": 0x029990, "unit": "rva"}
        ]
    })
}
