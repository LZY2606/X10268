use crate::domain::u32le;
use serde_json::json;

pub const EXPECTED_BASE: u32 = 0x1400_0000;
pub const ACTUAL_BASE_V1: u32 = 0x1500_0000;
pub const ACTUAL_BASE_V2: u32 = 0x1500_1000;
pub const HEADERS_SIZE: u32 = 0x400;
pub const SIZE_OF_IMAGE: u32 = 0x5000;

pub const TEXT_VA: u32 = 0x1000;
pub const RDATA_VA: u32 = 0x2000;
pub const DATA_VA: u32 = 0x3800;
pub const BSS_VA: u32 = 0x4100;

pub const TEXT_RAW: u32 = 0x400;
pub const RDATA_RAW: u32 = 0x700;
pub const DATA_RAW: u32 = 0x1c00;
pub const BSS_RAW: u32 = 0x1e00;

pub const EXPORT_RVA: u32 = 0x2000;
pub const IMPORT_RVA: u32 = 0x2100;
pub const KERNEL_NAME_RVA: u32 = 0x2200;
pub const LEGACY_NAME_RVA: u32 = 0x2240;
pub const MISSING_NAME_RVA: u32 = 0x2280;
pub const KERNEL_ILT_RVA: u32 = 0x2300;
pub const LEGACY_ILT_RVA: u32 = 0x2310;
pub const MISSING_ILT_RVA: u32 = 0x2320;
pub const IAT_RVA: u32 = 0x3800;
pub const HINT_LOAD_LIBRARY: u32 = 0x2500;
pub const HINT_OLD_API: u32 = 0x2560;
pub const HINT_FORWARD_API: u32 = 0x25a0;
pub const HINT_GHOST_API: u32 = 0x25e0;
pub const RELOC_RVA: u32 = 0x3a00;
pub const CORRUPT_DIRECTORY_RVA: u32 = 0x4ff0;

fn put_u16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_cstr(bytes: &mut [u8], at: usize, text: &str) {
    for (index, byte) in text.bytes().enumerate() {
        bytes[at + index] = byte;
    }
}

fn section_header(bytes: &mut [u8], at: usize, name: &[u8; 8], virtual_size: u32, virtual_address: u32, raw_size: u32, raw_offset: u32, characteristics: u32) {
    bytes[at..at + 8].copy_from_slice(name);
    put_u32(bytes, at + 8, virtual_size);
    put_u32(bytes, at + 12, virtual_address);
    put_u32(bytes, at + 16, raw_size);
    put_u32(bytes, at + 20, raw_offset);
    put_u32(bytes, at + 36, characteristics);
}

pub fn build_pe() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x2100];
    bytes[0..2].copy_from_slice(b"MZ");
    put_u16(&mut bytes, 0x3c, 0x80);
    bytes[0x40..0x44].copy_from_slice(b"PE!");

    let pe = 0x80;
    bytes[pe..pe + 4].copy_from_slice(b"PE\0\0");
    let coff = pe + 4;
    put_u16(&mut bytes, coff, 0x14c);
    put_u16(&mut bytes, coff + 2, 4);
    put_u32(&mut bytes, coff + 4, 0x1337_2026);
    put_u16(&mut bytes, coff + 16, 0xe0);
    put_u16(&mut bytes, coff + 18, 0x0102);

    let opt = coff + 20;
    put_u16(&mut bytes, opt, 0x10b);
    bytes[opt + 2] = 14;
    bytes[opt + 3] = 0;
    put_u32(&mut bytes, opt + 4, 0x300);
    put_u32(&mut bytes, opt + 8, 0x1d00);
    put_u32(&mut bytes, opt + 16, ENTRY_POINT_RVA);
    put_u32(&mut bytes, opt + 20, TEXT_VA);
    put_u32(&mut bytes, opt + 24, RDATA_VA);
    put_u32(&mut bytes, opt + 28, EXPECTED_BASE);
    put_u32(&mut bytes, opt + 32, 0x1000);
    put_u32(&mut bytes, opt + 36, 0x200);
    put_u16(&mut bytes, opt + 40, 4);
    put_u16(&mut bytes, opt + 42, 0);
    put_u16(&mut bytes, opt + 44, 0);
    put_u16(&mut bytes, opt + 46, 0);
    put_u32(&mut bytes, opt + 56, 0);
    put_u32(&mut bytes, opt + 60, 0);
    put_u32(&mut bytes, opt + 64, SIZE_OF_IMAGE);
    put_u32(&mut bytes, opt + 68, HEADERS_SIZE);
    put_u16(&mut bytes, opt + 70, 3);
    put_u16(&mut bytes, opt + 72, 0x0040);
    put_u32(&mut bytes, opt + 92, 16);

    put_u32(&mut bytes, opt + 96, EXPORT_RVA);
    put_u32(&mut bytes, opt + 100, 40);
    put_u32(&mut bytes, opt + 104, IMPORT_RVA);
    put_u32(&mut bytes, opt + 108, 60);
    put_u32(&mut bytes, opt + 112, IAT_RVA);
    put_u32(&mut bytes, opt + 116, 0x40);
    put_u32(&mut bytes, opt + 144, RELOC_RVA);
    put_u32(&mut bytes, opt + 148, 0x28);
    put_u32(&mut bytes, opt + 168, CORRUPT_DIRECTORY_RVA);
    put_u32(&mut bytes, opt + 172, 0x20);

    let section_table = opt + 0xe0;
    section_header(&mut bytes, section_table, b".text\0\0\0", 0x1000, TEXT_VA, 0x300, TEXT_RAW, 0x60000020);
    section_header(&mut bytes, section_table + 40, b".rdata\0\0", 0x1800, RDATA_VA, 0x1500, RDATA_RAW, 0x40000040);
    section_header(&mut bytes, section_table + 80, b".data\0\0\0", 0x1000, DATA_VA, 0x500, DATA_RAW, 0xc0000040);
    section_header(&mut bytes, section_table + 120, b".bss\0\0\0\0", 0x600, BSS_VA, 0x300, BSS_RAW, 0xc0000080);

    put_u32(&mut bytes, RDATA_RAW as usize + 12, 0x20c0);
    put_u32(&mut bytes, RDATA_RAW as usize + 16, 1);
    put_u32(&mut bytes, RDATA_RAW as usize + 20, 0x2000);
    put_u32(&mut bytes, RDATA_RAW as usize + 24, 1);
    put_u32(&mut bytes, RDATA_RAW as usize + 28, 1);

    let descriptor = IMPORT_RVA - RDATA_VA + RDATA_RAW;
    let mut desc = descriptor as usize;
    for (ilt, name, iat) in [
        (KERNEL_ILT_RVA, KERNEL_NAME_RVA, IAT_RVA),
        (LEGACY_ILT_RVA, LEGACY_NAME_RVA, IAT_RVA + 0x10),
        (MISSING_ILT_RVA, MISSING_NAME_RVA, IAT_RVA + 0x20),
    ] {
        put_u32(&mut bytes, desc, ilt);
        put_u32(&mut bytes, desc + 12, name);
        put_u32(&mut bytes, desc + 16, iat);
        desc += 20;
    }

    put_cstr(&mut bytes, (KERNEL_NAME_RVA - RDATA_VA + RDATA_RAW) as usize, "KERNEL32.dll");
    put_cstr(&mut bytes, (LEGACY_NAME_RVA - RDATA_VA + RDATA_RAW) as usize, "LEGACY.dll");
    put_cstr(&mut bytes, (MISSING_NAME_RVA - RDATA_VA + RDATA_RAW) as usize, "MISSING.dll");

    put_u32(&mut bytes, (KERNEL_ILT_RVA - RDATA_VA + RDATA_RAW) as usize, HINT_LOAD_LIBRARY);
    put_u32(&mut bytes, (KERNEL_ILT_RVA - RDATA_VA + RDATA_RAW + 4) as usize, 0x8000_0007);
    put_u32(&mut bytes, (LEGACY_ILT_RVA - RDATA_VA + RDATA_RAW) as usize, HINT_OLD_API);
    put_u32(&mut bytes, (LEGACY_ILT_RVA - RDATA_VA + RDATA_RAW + 4) as usize, HINT_FORWARD_API);
    put_u32(&mut bytes, (MISSING_ILT_RVA - RDATA_VA + RDATA_RAW) as usize, HINT_GHOST_API);

    let iat = IAT_RVA - DATA_VA + DATA_RAW;
    bytes[iat as usize..iat as usize + 0x30].copy_from_slice(&bytes[(KERNEL_ILT_RVA - RDATA_VA + RDATA_RAW) as usize..(KERNEL_ILT_RVA - RDATA_VA + RDATA_RAW) as usize + 0x30]);

    put_u16(&mut bytes, (HINT_LOAD_LIBRARY - RDATA_VA + RDATA_RAW) as usize, 101);
    put_cstr(&mut bytes, (HINT_LOAD_LIBRARY - RDATA_VA + RDATA_RAW + 2) as usize, "LoadLibraryA");
    put_u16(&mut bytes, (HINT_OLD_API - RDATA_VA + RDATA_RAW) as usize, 2);
    put_cstr(&mut bytes, (HINT_OLD_API - RDATA_VA + RDATA_RAW + 2) as usize, "OldApi");
    put_u16(&mut bytes, (HINT_FORWARD_API - RDATA_VA + RDATA_RAW) as usize, 3);
    put_cstr(&mut bytes, (HINT_FORWARD_API - RDATA_VA + RDATA_RAW + 2) as usize, "ForwardApi");
    put_u16(&mut bytes, (HINT_GHOST_API - RDATA_VA + RDATA_RAW) as usize, 1);
    put_cstr(&mut bytes, (HINT_GHOST_API - RDATA_VA + RDATA_RAW + 2) as usize, "GhostApi");

    let reloc = RELOC_RVA - DATA_VA + DATA_RAW;
    put_u32(&mut bytes, reloc as usize, 0x1000);
    put_u32(&mut bytes, reloc as usize + 4, 16);
    put_u16(&mut bytes, reloc as usize + 8, 0x3000);
    put_u16(&mut bytes, reloc as usize + 10, 0x3008);
    put_u32(&mut bytes, reloc as usize + 12, 0x4000);
    put_u32(&mut bytes, reloc as usize + 16, 12);
    put_u16(&mut bytes, reloc as usize + 20, 0x30f8);
    put_u32(&mut bytes, reloc as usize + 24, 0x4000);
    put_u32(&mut bytes, reloc as usize + 28, 12);
    put_u16(&mut bytes, reloc as usize + 32, 0xa6f8);

    for offset in [0x400, 0x408, 0xf00, reloc as u32] {
        if offset + 8 <= bytes.len() as u32 {
            let marker = 0xa5a5_0000 | offset;
            put_u32(&mut bytes, offset as usize, marker);
        }
    }
    let _ = u32le;
    bytes
}

pub const ENTRY_POINT_RVA: u32 = 0x1000;

pub fn snapshot_v1() -> serde_json::Value {
    json!({
      "schema": "dll-export-snapshot/v1",
      "coordinate_basis": {"address_unit": "byte", "rva_origin": "loaded DLL image base", "ordinal_basis": "export ordinal table"},
      "dlls": [
        {"name":"KERNEL32.dll","exports":[
          {"name":"LoadLibraryA","ordinal":101,"rva":"0x1000","forwarded_to":null},
          {"name":"ControlDevice","ordinal":7,"rva":"0x1700","forwarded_to":null}
        ]},
        {"name":"LEGACY.dll","exports":[
          {"name":"OldApi","ordinal":2,"rva":"0x2000","forwarded_to":null},
          {"name":"ForwardApi","ordinal":3,"rva":null,"forwarded_to":"FORWARD.Worker"}
        ]},
        {"name":"FORWARD.dll","exports":[
          {"name":"Worker","ordinal":9,"rva":"0x3000","forwarded_to":null}
        ]}
      ]
    })
}

pub fn snapshot_v2() -> serde_json::Value {
    let mut value = snapshot_v1();
    value["dlls"][0]["exports"][0]["rva"] = json!("0x1234");
    value["schema"] = json!("dll-export-snapshot/v2-local-kernel32-revision");
    value
}
