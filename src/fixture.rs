use serde_json::json;

use crate::model::Material;

pub const PE_ID: &str = "material-pe-bytes";
pub const SNAPSHOT_ID: &str = "material-dll-export-snapshot";
pub const IMAGE_BASE_ID: &str = "material-expected-image-base";

pub const INITIAL_BASE: u64 = 0x14000_0000;
pub const INITIAL_BASE_HEX: &str = "0x140000000 u64[VA]";
pub const ALTERNATE_BASE: u64 = 0x18000_0000;

pub const FILE_SIZE: usize = 0x600;
pub const HEADERS_SIZE: u32 = 0x400;
pub const SIZE_OF_IMAGE: u32 = 0x5000;

pub const TEXT_VA: u32 = 0x1000;
pub const TEXT_VS: u32 = 0x1200;
pub const TEXT_RAW_PTR: u32 = 0x400;
pub const TEXT_RAW_SIZE: u32 = 0x100;

pub const RDATA_VA: u32 = 0x2000;
pub const RDATA_VS: u32 = 0x1200;
pub const RDATA_RAW_PTR: u32 = 0x440;
pub const RDATA_RAW_SIZE: u32 = 0x100;

pub const OVLP_VA: u32 = 0x3100;
pub const OVLP_VS: u32 = 0x200;
pub const OVLP_RAW_PTR: u32 = 0x200;
pub const OVLP_RAW_SIZE: u32 = 0x140;

pub const RELOC_VA: u32 = 0x4000;
pub const RELOC_VS: u32 = 0x100;
pub const RELOC_RAW_PTR: u32 = 0x200;
pub const RELOC_RAW_SIZE: u32 = 0x100;

pub const EXPORT_RVA: u32 = 0x2000;
pub const EXPORT_SIZE: u32 = 0xf0;
pub const IMPORT_RVA: u32 = 0x2040;
pub const IMPORT_SIZE: u32 = 0x3c;
pub const RELOC_DIR_RVA: u32 = 0x4000;
pub const RELOC_DIR_SIZE: u32 = 0x20;
pub const IAT_RVA: u32 = 0x2100;
pub const IAT_SIZE: u32 = 0x18;
pub const DEBUG_RVA: u32 = 0xffff_0000;
pub const DEBUG_SIZE: u32 = 0x28;

pub fn build_pe_bytes() -> Vec<u8> {
    let mut b = vec![0u8; FILE_SIZE];
    b[0] = b'M';
    b[1] = b'Z';
    put_u32(&mut b, 0x3c, 0x80);
    put_u32(&mut b, 0x80, 0x0000_4550);
    put_u16(&mut b, 0x84, 0x8664);
    put_u16(&mut b, 0x86, 4);
    put_u16(&mut b, 0x94, 0x00f0);
    put_u16(&mut b, 0x96, 0x0022);
    put_u16(&mut b, 0x98, 0x20b);
    put_u32(&mut b, 0x9c, 0x1000);
    put_u32(&mut b, 0xa0, 0x1000);
    put_u32(&mut b, 0xa4, 0x1000);
    put_u32(&mut b, 0xa8, 0x1000);
    put_u32(&mut b, 0xac, 0x1000);
    put_u64(&mut b, 0xb0, INITIAL_BASE);
    put_u32(&mut b, 0xb8, 0x1000);
    put_u32(&mut b, 0xbc, 0x200);
    put_u16(&mut b, 0xc0, 6);
    put_u16(&mut b, 0xc4, 0);
    put_u16(&mut b, 0xc8, 6);
    put_u32(&mut b, 0xd0, SIZE_OF_IMAGE);
    put_u32(&mut b, 0xd4, HEADERS_SIZE);
    put_u16(&mut b, 0xdc, 3);
    put_u64(&mut b, 0xe0, 0x100000);
    put_u64(&mut b, 0xe8, 0x1000);
    put_u64(&mut b, 0xf0, 0x100000);
    put_u64(&mut b, 0xf8, 0x1000);
    put_u32(&mut b, 0x104, 16);
    put_dir(&mut b, 0x108, 0, EXPORT_RVA, EXPORT_SIZE);
    put_dir(&mut b, 0x108, 1, IMPORT_RVA, IMPORT_SIZE);
    put_dir(&mut b, 0x108, 5, RELOC_DIR_RVA, RELOC_DIR_SIZE);
    put_dir(&mut b, 0x108, 6, DEBUG_RVA, DEBUG_SIZE);
    put_dir(&mut b, 0x108, 12, IAT_RVA, IAT_SIZE);

    put_section(&mut b, 0x188, b".text\0\0\0", TEXT_VS, TEXT_VA, TEXT_RAW_SIZE, TEXT_RAW_PTR);
    put_section(&mut b, 0x1b0, b".rdata\0\0", RDATA_VS, RDATA_VA, RDATA_RAW_SIZE, RDATA_RAW_PTR);
    put_section(&mut b, 0x1d8, b".ovlp\0\0\0", OVLP_VS, OVLP_VA, OVLP_RAW_SIZE, OVLP_RAW_PTR);
    put_section(&mut b, 0x200, b".reloc\0\0", RELOC_VS, RELOC_VA, RELOC_RAW_SIZE, RELOC_RAW_PTR);

    populate_directories(&mut b);
    b
}

pub fn put_u16(b: &mut [u8], off: usize, value: u16) {
    b[off..off + 2].copy_from_slice(&value.to_le_bytes());
}

pub fn put_u32(b: &mut [u8], off: usize, value: u32) {
    b[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

pub fn put_u64(b: &mut [u8], off: usize, value: u64) {
    b[off..off + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_dir(b: &mut [u8], base: usize, index: usize, rva: u32, size: u32) {
    let off = base + index * 8;
    put_u32(b, off, rva);
    put_u32(b, off + 4, size);
}

fn put_section(b: &mut [u8], off: usize, name: &[u8; 8], vs: u32, va: u32, rs: u32, rp: u32) {
    b[off..off + 8].copy_from_slice(name);
    put_u32(b, off + 8, vs);
    put_u32(b, off + 12, va);
    put_u32(b, off + 16, rs);
    put_u32(b, off + 20, rp);
    put_u16(b, off + 36, 0x6000_0020);
}

fn rdata_off(rva: u32) -> usize {
    (RDATA_RAW_PTR + (rva - RDATA_VA)) as usize
}

fn reloc_off(rva: u32) -> usize {
    (RELOC_RAW_PTR + (rva - RELOC_VA)) as usize
}

fn put_cstr(b: &mut [u8], off: usize, text: &str) {
    b[off..off + text.len()].copy_from_slice(text.as_bytes());
}

fn populate_directories(b: &mut [u8]) {
    put_u32(b, rdata_off(0x2000), 0);
    put_u32(b, rdata_off(0x2004), 1);
    put_u16(b, rdata_off(0x2008), 0);
    put_u16(b, rdata_off(0x200a), 0);
    put_u32(b, rdata_off(0x200c), 0);
    put_u32(b, rdata_off(0x2010), 0);
    put_u32(b, rdata_off(0x2014), 0);
    put_u32(b, rdata_off(0x2018), 0x2028);
    put_u32(b, rdata_off(0x201c), 2);
    put_u32(b, rdata_off(0x2020), 2);
    put_u32(b, rdata_off(0x2024), 0x2030);
    put_u32(b, rdata_off(0x2028), 0x1010);
    put_u32(b, rdata_off(0x202c), 0x20ee);
    put_u32(b, rdata_off(0x2030), 0x20da);
    put_u32(b, rdata_off(0x2034), 0x20e4);
    put_u16(b, rdata_off(0x2038), 0);
    put_u16(b, rdata_off(0x203a), 1);
    put_u32(b, rdata_off(0x203c), 0x20c0);

    put_import_descriptor(b, 0x2040, 0x2080, 0x20c0, IAT_RVA);
    put_import_descriptor(b, 0x2054, 0x2098, 0x20cc, 0x2110);

    put_u64(b, rdata_off(0x2080), 0x20da);
    put_u64(b, rdata_off(0x2088), 0x20e4);
    put_u64(b, rdata_off(0x2098), 0x8000_0000_0000_0007);

    put_cstr(b, rdata_off(0x20c0), "feature.dll\0");
    put_cstr(b, rdata_off(0x20cc), "missing.dll\0");
    put_cstr(b, rdata_off(0x20da), "\0\0DoThing\0");
    put_cstr(b, rdata_off(0x20e4), "\0\0Forwarded\0");
    put_cstr(b, rdata_off(0x20ee), "kernel32.HeapAlloc\0");

    put_u64(b, 0x408, 0x14000_1000);
    put_u32(b, 0x448, 0xf000_0000);
    put_relocation_block(b, 0x4000, 0x1000, &[(10, 0x008), (0, 0)]);
    put_relocation_block(b, 0x400c, 0x2000, &[(10, 0x008)]);
    let overflow_rva = 0xffff_0008u32;
    put_u32(b, reloc_off(0x4016), overflow_rva);
    put_u32(b, reloc_off(0x401a), 10);
    put_u16(b, reloc_off(0x401e), 0xa00);
}

fn put_import_descriptor(b: &mut [u8], off: u32, ilt: u32, name: u32, iat: u32) {
    let p = rdata_off(off);
    put_u32(b, p, ilt);
    put_u32(b, p + 12, name);
    put_u32(b, p + 16, iat);
}

fn put_relocation_block(b: &mut [u8], page: u32, page_rva: u32, entries: &[(u16, u16)]) {
    let p = reloc_off(page);
    put_u32(b, p, page_rva);
    put_u32(b, p + 4, 8 + (entries.len() as u32) * 2);
    for (i, entry) in entries.iter().enumerate() {
        put_u16(b, p + 8 + i * 2, (entry.0 << 12) | entry.1);
    }
}

pub fn build_initial_materials() -> Vec<Material> {
    let pe = build_pe_bytes();
    let pe_repr = json!({
        "kind": "PE32+",
        "coordinate_basis": "file-offset:0[byte], RVA:0[byte-from-image-base], VA:image-base+RVA",
        "byte_order": "little-endian",
        "expected_units": "u16[word],u32[doubleword],u64[quadword],RVA[byte],VA[byte]",
        "source_preservation": "all imported bytes remain in bytes; parser results are stored as derived candidates"
    });
    let snapshot_repr = snapshot_v1();
    let base_repr = json!({
        "expected_image_base": INITIAL_BASE_HEX,
        "coordinate_basis": "VA[byte] = expected_image_base + RVA[byte]",
        "source": "reverse-engineering intake form"
    });
    vec![
        Material {
            material_id: PE_ID.to_string(),
            kind: "pe-bytes".into(),
            label: "offline PE loader mirror fixture".into(),
            revision: 1,
            original_representation: pe_repr,
            bytes: hex::encode(&pe),
            byte_encoding: "hex/binary".into(),
            supersedes: None,
        },
        Material {
            material_id: SNAPSHOT_ID.to_string(),
            kind: "dll-export-snapshot".into(),
            label: "optional local DLL export snapshot".into(),
            revision: 1,
            original_representation: snapshot_repr,
            bytes: bytes_for_json(&snapshot_v1()),
            byte_encoding: "utf-8/json".into(),
            supersedes: None,
        },
        Material {
            material_id: IMAGE_BASE_ID.to_string(),
            kind: "expected-image-base".into(),
            label: "expected image base".into(),
            revision: 1,
            original_representation: base_repr,
            bytes: bytes_for_json(&base_material_json(INITIAL_BASE_HEX)),
            byte_encoding: "utf-8/json".into(),
            supersedes: None,
        },
    ]
}

pub fn build_revised_snapshot_material() -> Material {
    let repr = snapshot_v2();
    Material {
        material_id: SNAPSHOT_ID.to_string(),
        kind: "dll-export-snapshot".into(),
        label: "local dependency-only DLL export snapshot revision".into(),
        revision: 2,
        original_representation: repr.clone(),
        bytes: bytes_for_json(&repr),
        byte_encoding: "utf-8/json".into(),
        supersedes: Some(format!("{SNAPSHOT_ID}:1")),
    }
}

pub fn snapshot_v1() -> serde_json::Value {
    json!({
        "coordinate_basis": "RVA[byte] is relative to the exporting module image base",
        "dlls": {
            "feature.dll": {
                "ordinal_base": "1[ordinal]",
                "exports": [
                    {
                        "name": "DoThing",
                        "ordinal": "1[ordinal]",
                        "rva": "0x1010[RVA-byte]",
                        "forwarded_from": null
                    },
                    {
                        "name": "Forwarded",
                        "ordinal": "2[ordinal]",
                        "rva": "0x2030[RVA-byte]",
                        "forwarder_string_rva": "0x203c[RVA-byte]",
                        "forwards_to": "kernel32.HeapAlloc"
                    }
                ]
            },
            "kernel32.dll": {
                "exports": [{ "name": "HeapAlloc", "ordinal": "48[ordinal]" }]
            }
        },
        "missing": ["missing.dll"]
    })
}

pub fn snapshot_v2() -> serde_json::Value {
    let mut value = snapshot_v1();
    value["dlls"]["feature.dll"]["exports"][0]["rva"] = json!("0x1040[RVA-byte]");
    value["change_note"] = json!("local source edit: only DoThing's export coordinate changes");
    value
}

fn base_material_json(base: &str) -> serde_json::Value {
    json!({
        "expected_image_base": base,
        "coordinate_basis": "VA[byte] = expected_image_base + RVA[byte]"
    })
}

pub fn revised_base_material(base: u64) -> Material {
    let repr = base_material_json(&format!("0x{base:x} u64[VA]"));
    Material {
        material_id: IMAGE_BASE_ID.to_string(),
        kind: "expected-image-base".into(),
        label: "revised expected image base".into(),
        revision: 2,
        original_representation: repr.clone(),
        bytes: bytes_for_json(&repr),
        byte_encoding: "utf-8/json".into(),
        supersedes: Some(format!("{IMAGE_BASE_ID}:1")),
    }
}

pub fn bytes_for_json(value: &serde_json::Value) -> String {
    let compact = serde_json::to_vec(value).expect("valid JSON");
    String::from_utf8(compact).expect("UTF-8 JSON")
}

pub fn json_span(value: &serde_json::Value, needle: &str) -> (u64, u64) {
    let raw = bytes_for_json(value);
    let pos = raw.find(needle).unwrap_or(0) as u64;
    (pos, needle.len() as u64)
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }
}
