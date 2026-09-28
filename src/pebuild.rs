//! Deterministic synthetic PE32+ case image used by the offline case package.
//!
//! Layout (all coordinates shown with their basis):
//!   file basis                virtual basis (RVA)
//!   0x000  headers            (size_of_headers = 0x400)
//!   0x400  .text   raw 0x600  0x1000 vsize 0x600  (DIR64 @0x1010, HIGHLOW @0x1020)
//!   0xa00  .ovlap  raw 0x200  0x1400 vsize 0x300  (virtual overlap with .text)
//!   0xc00  .data   raw 0x100  0x2000 vsize 0x300  (vsize > raw => zero-fill tail)
//!   0xe00  .rdata  raw 0x600  0x3000 vsize 0x600  (import tables)
//!   0x1400 .reloc  raw 0x200  0x4000 vsize 0x200
//! The DEBUG directory deliberately points at RVA 0x9000 (outside the image).

pub const PREFERRED_BASE: u64 = 0x14000_0000;

struct Img {
    b: Vec<u8>,
}

impl Img {
    fn new(len: usize) -> Self {
        Img { b: vec![0u8; len] }
    }
    fn put(&mut self, off: usize, bytes: &[u8]) {
        self.b[off..off + bytes.len()].copy_from_slice(bytes);
    }
    fn u16(&mut self, off: usize, v: u16) {
        self.put(off, &v.to_le_bytes());
    }
    fn u32(&mut self, off: usize, v: u32) {
        self.put(off, &v.to_le_bytes());
    }
    fn u64(&mut self, off: usize, v: u64) {
        self.put(off, &v.to_le_bytes());
    }
    fn cstr(&mut self, off: usize, s: &str) {
        self.put(off, s.as_bytes());
    }
}

const RDATA_RAW: u32 = 0xe00;
const RDATA_VA: u32 = 0x3000;

fn rd(rva: u32) -> usize {
    (RDATA_RAW + (rva - RDATA_VA)) as usize
}

pub fn build_case_pe() -> Vec<u8> {
    let mut img = Img::new(0x1600);
    // --- DOS header ---
    img.put(0, b"MZ");
    img.u32(0x3c, 0x40);
    // --- NT signature + COFF header (PE32+) ---
    img.u32(0x40, 0x0000_4550);
    img.u16(0x44, 0x8664); // machine AMD64
    img.u16(0x46, 5); // number of sections
    img.u16(0x54, 240); // size of optional header
    img.u16(0x56, 0x0022); // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    // --- optional header ---
    let opt = 0x58usize;
    img.u16(opt, 0x20b); // PE32+
    img.u32(opt + 4, 0x600); // size of code
    img.u32(opt + 16, 0x1000); // entry point RVA
    img.u64(opt + 24, PREFERRED_BASE);
    img.u32(opt + 32, 0x1000); // section alignment
    img.u32(opt + 36, 0x200); // file alignment
    img.u32(opt + 56, 0x5000); // size of image
    img.u32(opt + 60, 0x400); // size of headers
    img.u16(opt + 68, 3); // subsystem: console
    img.u32(opt + 108, 16); // number of data directories
    let dirs = opt + 112;
    img.u32(dirs + 1 * 8, RDATA_VA); // IMPORT
    img.u32(dirs + 1 * 8 + 4, 5 * 20);
    img.u32(dirs + 5 * 8, 0x4000); // BASERELOC
    img.u32(dirs + 5 * 8 + 4, 12);
    img.u32(dirs + 6 * 8, 0x9000); // DEBUG: deliberately outside the image
    img.u32(dirs + 6 * 8 + 4, 0x1c);
    // --- section table at 0x148 ---
    let st = 0x148usize;
    let secs: [(&str, u32, u32, u32, u32, u32); 5] = [
        (".text", 0x600, 0x1000, 0x600, 0x400, 0x6000_0020),
        (".ovlap", 0x300, 0x1400, 0x200, 0xa00, 0xc000_0040),
        (".data", 0x300, 0x2000, 0x100, 0xc00, 0xc000_0040),
        (".rdata", 0x600, 0x3000, 0x600, 0xe00, 0x4000_0040),
        (".reloc", 0x200, 0x4000, 0x200, 0x1400, 0x4200_0040),
    ];
    for (i, (name, vs, va, rs, rp, ch)) in secs.iter().enumerate() {
        let s = st + i * 40;
        img.cstr(s, name);
        img.u32(s + 8, *vs);
        img.u32(s + 12, *va);
        img.u32(s + 16, *rs);
        img.u32(s + 20, *rp);
        img.u32(s + 36, *ch);
    }
    // --- raw section contents ---
    for f in 0x400..0xa00 {
        img.b[f] = 0xcc;
    }
    for f in 0xa00..0xc00 {
        img.b[f] = 0xaa;
    }
    for f in 0xc00..0xd00 {
        img.b[f] = 0xdd;
    }
    // DIR64 field @ RVA 0x1010 -> file 0x410; HIGHLOW field @ RVA 0x1020 -> 0x420
    img.u64(0x410, PREFERRED_BASE + 0x1010);
    img.u32(0x420, 0x0040_1020);

    // --- import tables inside .rdata ---
    let mut cur = RDATA_VA;
    let mut alloc = |n: u32| {
        let rva = cur;
        cur += n;
        rva
    };
    let desc_rva = alloc(5 * 20);
    struct Imp {
        dll: &'static str,
        ilt: u32,
        iat: u32,
        name_rva: u32,
    }
    let mut imps: Vec<Imp> = Vec::new();
    for dll in ["KERNEL32.dll", "ORDONLY.dll", "MISSING.dll", "FWDSINK.dll"] {
        let ilt = alloc(16);
        let iat = alloc(16);
        let name_rva = alloc(dll.len() as u32 + 1);
        imps.push(Imp { dll, ilt, iat, name_rva });
    }
    let hn_gettick = alloc(2 + 14);
    let hn_nosuch = alloc(2 + 11);
    let hn_forward = alloc(2 + 10);
    let desc0 = desc_rva as usize;
    let _ = desc0;
    for (i, im) in imps.iter().enumerate() {
        img.cstr(rd(im.name_rva), im.dll);
        let d = rd(desc_rva + i as u32 * 20);
        img.u32(d, im.ilt); // OriginalFirstThunk
        img.u32(d + 12, im.name_rva); // Name
        img.u32(d + 16, im.iat); // FirstThunk
    }
    // hint/name blobs
    img.u16(rd(hn_gettick), 0);
    img.cstr(rd(hn_gettick) + 2, "GetTickCount");
    img.u16(rd(hn_nosuch), 0);
    img.cstr(rd(hn_nosuch) + 2, "NoSuchFunc");
    img.u16(rd(hn_forward), 0);
    img.cstr(rd(hn_forward) + 2, "ForwardMe");
    // thunk values
    img.u64(rd(imps[0].ilt), hn_gettick as u64);
    img.u64(rd(imps[0].iat), hn_gettick as u64);
    img.u64(rd(imps[1].ilt), (1u64 << 63) | 42); // ordinal import #42
    img.u64(rd(imps[1].iat), (1u64 << 63) | 42);
    img.u64(rd(imps[2].ilt), hn_nosuch as u64);
    img.u64(rd(imps[2].iat), hn_nosuch as u64);
    img.u64(rd(imps[3].ilt), hn_forward as u64);
    img.u64(rd(imps[3].iat), hn_forward as u64);

    // --- .reloc block ---
    img.u32(0x1400, 0x1000); // page RVA
    img.u32(0x1404, 12); // block size: 8-byte header + 2 entries
    img.u16(0x1408, (10 << 12) | 0x010); // DIR64 @ RVA 0x1010
    img.u16(0x140a, (3 << 12) | 0x020); // HIGHLOW @ RVA 0x1020

    img.b
}
