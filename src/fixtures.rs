//! Deterministic PE fixtures covering the edge-case matrix. Bytes are built
//! in code so the repo carries a regenerable, reviewable case package.

pub const EXPECTED_IMAGE_BASE: u64 = 0x1_4000_0000;
pub const REVISED_IMAGE_BASE: u64 = 0x1_8000_0000;

pub struct B {
    image_base: u64,
    secs: Vec<Sec>,
    dirs: [(u32, u32); 16],
}

struct Sec {
    name: &'static str,
    vsize: u32,
    data: Vec<u8>,
    chars: u32,
    va: Option<u32>,
}

pub enum ThunkSpec {
    Name(&'static str),
    Ordinal(u16),
}

impl B {
    pub fn new() -> B {
        B { image_base: EXPECTED_IMAGE_BASE, secs: Vec::new(), dirs: [(0, 0); 16] }
    }
    pub fn sec(&mut self, name: &'static str, vsize: u32, chars: u32) -> usize {
        self.secs.push(Sec { name, vsize, data: Vec::new(), chars, va: None });
        self.secs.len() - 1
    }
    pub fn sec_at(&mut self, name: &'static str, va: u32, vsize: u32, chars: u32) -> usize {
        self.secs.push(Sec { name, vsize, data: Vec::new(), chars, va: Some(va) });
        self.secs.len() - 1
    }
    pub fn put(&mut self, s: usize, data: &[u8]) -> u32 {
        let off = self.secs[s].data.len() as u32;
        self.secs[s].data.extend_from_slice(data);
        off
    }
    pub fn put_at(&mut self, s: usize, off: u32, data: &[u8]) {
        let end = off as usize + data.len();
        if self.secs[s].data.len() < end {
            self.secs[s].data.resize(end, 0);
        }
        self.secs[s].data[off as usize..end].copy_from_slice(data);
    }
    pub fn va_of(&self, s: usize) -> u32 {
        self.secs[s].va.unwrap_or(0x1000 * (s as u32 + 1))
    }
    pub fn rva(&self, s: usize, off: u32) -> u32 {
        self.va_of(s) + off
    }
    pub fn dir(&mut self, idx: usize, rva: u32, size: u32) {
        self.dirs[idx] = (rva, size);
    }
    pub fn build(&self) -> Vec<u8> {
        let n = self.secs.len();
        let headers = 0x200usize;
        let mut raw_ptrs = Vec::new();
        let mut cursor = headers as u32;
        for s in &self.secs {
            raw_ptrs.push(cursor);
            let raw_size = align(s.data.len() as u32, 0x200);
            cursor += raw_size;
        }
        let mut top = 0u32;
        for (i, s) in self.secs.iter().enumerate() {
            top = top.max(self.va_of(i) + s.vsize.max(align(s.data.len() as u32, 1)));
        }
        let size_of_image = align(top, 0x1000);

        let mut out = vec![0u8; cursor as usize];
        // DOS header
        out[0] = b'M';
        out[1] = b'Z';
        out[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        // NT signature + COFF
        out[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        out[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        out[coff + 2..coff + 4].copy_from_slice(&(n as u16).to_le_bytes());
        out[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes());
        out[coff + 18..coff + 20].copy_from_slice(&0x2022u16.to_le_bytes());
        // Optional header PE32+
        let opt = coff + 20;
        out[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        out[opt + 20..opt + 24].copy_from_slice(&0x1000u32.to_le_bytes());
        out[opt + 24..opt + 32].copy_from_slice(&self.image_base.to_le_bytes());
        out[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        out[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
        out[opt + 56..opt + 60].copy_from_slice(&size_of_image.to_le_bytes());
        out[opt + 60..opt + 64].copy_from_slice(&(headers as u32).to_le_bytes());
        out[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());
        out[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
        for (i, (rva, size)) in self.dirs.iter().enumerate() {
            let o = opt + 112 + i * 8;
            out[o..o + 4].copy_from_slice(&rva.to_le_bytes());
            out[o + 4..o + 8].copy_from_slice(&size.to_le_bytes());
        }
        // Section headers
        let sh = opt + 240;
        for (i, s) in self.secs.iter().enumerate() {
            let o = sh + i * 40;
            let mut name = [0u8; 8];
            name[..s.name.len().min(8)].copy_from_slice(&s.name.as_bytes()[..s.name.len().min(8)]);
            out[o..o + 8].copy_from_slice(&name);
            out[o + 8..o + 12].copy_from_slice(&s.vsize.to_le_bytes());
            out[o + 12..o + 16].copy_from_slice(&self.va_of(i).to_le_bytes());
            let raw_size = align(s.data.len() as u32, 0x200);
            out[o + 16..o + 20].copy_from_slice(&raw_size.to_le_bytes());
            out[o + 20..o + 24].copy_from_slice(&raw_ptrs[i].to_le_bytes());
            out[o + 36..o + 40].copy_from_slice(&s.chars.to_le_bytes());
            out[raw_ptrs[i] as usize..raw_ptrs[i] as usize + s.data.len()]
                .copy_from_slice(&s.data);
        }
        out
    }
}

fn align(v: u32, a: u32) -> u32 {
    (v + a - 1) / a * a
}

fn hint_name(n: &str) -> Vec<u8> {
    let mut v = vec![0u8, 0u8];
    v.extend_from_slice(n.as_bytes());
    v.push(0);
    if v.len() % 2 == 1 {
        v.push(0);
    }
    v
}

fn build_imports(b: &mut B, sec: usize, dlls: &[(&str, Vec<ThunkSpec>)]) -> (u32, u32) {
    let mut ilt_offs = Vec::new();
    let mut iat_offs = Vec::new();
    for (_, thunks) in dlls {
        ilt_offs.push(b.put(sec, &vec![0u8; (thunks.len() + 1) * 8]));
        iat_offs.push(b.put(sec, &vec![0u8; (thunks.len() + 1) * 8]));
    }
    let desc_off = b.put(sec, &vec![0u8; dlls.len() * 20 + 20]);
    for (i, (dll, thunks)) in dlls.iter().enumerate() {
        let dll_name_off = b.put(sec, format!("{dll}\0").as_bytes());
        let mut ilt = Vec::new();
        for t in thunks {
            let val = match t {
                ThunkSpec::Ordinal(o) => 0x8000_0000_0000_0000u64 | *o as u64,
                ThunkSpec::Name(n) => {
                    let hn = b.put(sec, &hint_name(n));
                    b.rva(sec, hn) as u64
                }
            };
            ilt.extend_from_slice(&val.to_le_bytes());
        }
        ilt.extend_from_slice(&0u64.to_le_bytes());
        b.put_at(sec, ilt_offs[i], &ilt);
        b.put_at(sec, iat_offs[i], &ilt);
        let mut d = [0u8; 20];
        d[0..4].copy_from_slice(&b.rva(sec, ilt_offs[i]).to_le_bytes());
        d[12..16].copy_from_slice(&b.rva(sec, dll_name_off).to_le_bytes());
        d[16..20].copy_from_slice(&b.rva(sec, iat_offs[i]).to_le_bytes());
        b.put_at(sec, desc_off + i as u32 * 20, &d);
    }
    (b.rva(sec, desc_off), (dlls.len() * 20 + 20) as u32)
}

fn reloc_block(page_rva: u32, entries: &[(u8, u16)]) -> Vec<u8> {
    let mut ents: Vec<u16> = entries.iter().map(|(t, o)| ((*t as u16) << 12) | o).collect();
    if ents.len() % 2 == 1 {
        ents.push(0);
    }
    let mut v = Vec::new();
    v.extend_from_slice(&page_rva.to_le_bytes());
    v.extend_from_slice(&(8 + ents.len() as u32 * 2).to_le_bytes());
    for e in ents {
        v.extend_from_slice(&e.to_le_bytes());
    }
    v
}

const CODE: u32 = 0x6000_0020;
const RDATA: u32 = 0xC000_0040;
const RELOC: u32 = 0x4200_0040;

fn text_section_with(b: &mut B, fill: &[(u32, &[u8])]) -> usize {
    let t = b.sec(".text", 0x200, CODE);
    b.put(t, &vec![0xCCu8; 0x200]);
    for (off, bytes) in fill {
        b.put_at(t, *off, bytes);
    }
    t
}

pub fn baseline() -> Vec<u8> {
    let mut b = B::new();
    let ptr = EXPECTED_IMAGE_BASE + 0x2000;
    let v32 = 0x4000_2000u32;
    text_section_with(&mut b, &[(0, &ptr.to_le_bytes()), (8, &v32.to_le_bytes())]);
    let rd = b.sec(".rdata", 0x200, RDATA);
    let (rva, size) = build_imports(
        &mut b,
        rd,
        &[("kernel32.dll", vec![ThunkSpec::Name("ExitProcess"), ThunkSpec::Name("GetTickCount")])],
    );
    b.dir(1, rva, size);
    let rc = b.sec(".reloc", 0x200, RELOC);
    let blk = reloc_block(0x1000, &[(10, 0), (3, 8)]);
    let blen = blk.len() as u32;
    let roff = b.put(rc, &blk);
    b.dir(5, b.rva(rc, roff), blen);
    b.build()
}

pub fn overlap() -> Vec<u8> {
    let mut b = B::new();
    text_section_with(&mut b, &[]);
    let id = b.sec_at(".idata", 0x1800, 0x400, RDATA); // overlaps .text range 0x1000..0x1a00
    let (rva, size) = build_imports(&mut b, id, &[("kernel32.dll", vec![ThunkSpec::Name("ExitProcess")])]);
    b.dir(1, rva, size);
    b.build()
}

pub fn vsize_gt_raw() -> Vec<u8> {
    let mut b = B::new();
    text_section_with(&mut b, &[]);
    let d = b.sec(".data", 0x1000, RDATA); // virtual 0x1000, raw only 0x200
    let ptr = EXPECTED_IMAGE_BASE + 0x1000;
    b.put(d, &ptr.to_le_bytes());
    b.put_at(d, 0x1FF, &[0xAA]);
    let rc = b.sec(".reloc", 0x200, RELOC);
    // DIR64 at 0x2000 (raw-backed) and DIR64 at 0x2200 (zero-fill only).
    let blk = reloc_block(0x2000, &[(10, 0), (10, 0x200)]);
    let blen = blk.len() as u32;
    let roff = b.put(rc, &blk);
    b.dir(5, b.rva(rc, roff), blen);
    b.build()
}

pub fn reloc_overflow() -> Vec<u8> {
    let mut b = B::new();
    let ptr = EXPECTED_IMAGE_BASE + 0x1000;
    text_section_with(&mut b, &[(0, &0xFFFF_FFF0u32.to_le_bytes()), (8, &ptr.to_le_bytes())]);
    let rc = b.sec(".reloc", 0x200, RELOC);
    let blk = reloc_block(0x1000, &[(3, 0), (10, 8)]);
    let blen = blk.len() as u32;
    let roff = b.put(rc, &blk);
    b.dir(5, b.rva(rc, roff), blen);
    b.build()
}

pub fn ordinal_import() -> Vec<u8> {
    let mut b = B::new();
    text_section_with(&mut b, &[]);
    let rd = b.sec(".rdata", 0x200, RDATA);
    let (rva, size) =
        build_imports(&mut b, rd, &[("ordonly.dll", vec![ThunkSpec::Ordinal(7), ThunkSpec::Ordinal(42)])]);
    b.dir(1, rva, size);
    b.build()
}

pub fn forwarded() -> Vec<u8> {
    let mut b = B::new();
    text_section_with(&mut b, &[]);
    let rd = b.sec(".rdata", 0x200, RDATA);
    let (rva, size) = build_imports(&mut b, rd, &[("fwd.dll", vec![ThunkSpec::Name("MiddleFunc")])]);
    b.dir(1, rva, size);
    b.build()
}

pub fn missing_dll() -> Vec<u8> {
    let mut b = B::new();
    text_section_with(&mut b, &[]);
    let rd = b.sec(".rdata", 0x200, RDATA);
    let (rva, size) = build_imports(&mut b, rd, &[("nosuch.dll", vec![ThunkSpec::Name("Ghost")])]);
    b.dir(1, rva, size);
    b.build()
}

pub fn corrupt_dir() -> Vec<u8> {
    let mut b = B::new();
    text_section_with(&mut b, &[]);
    let rd = b.sec(".rdata", 0x200, RDATA);
    let (rva, size) = build_imports(&mut b, rd, &[("kernel32.dll", vec![ThunkSpec::Name("ExitProcess")])]);
    b.dir(1, rva, size);
    let rc = b.sec(".reloc", 0x200, RELOC);
    let blk = reloc_block(0x1000, &[(10, 0)]);
    b.put(rc, &blk);
    // Directory points outside the image: must be diagnosed, not followed.
    b.dir(5, 0x0009_0000, 0x100);
    b.build()
}

pub fn pe_fixtures() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("baseline.exe", baseline()),
        ("overlap.exe", overlap()),
        ("vsize_gt_raw.exe", vsize_gt_raw()),
        ("reloc_overflow.exe", reloc_overflow()),
        ("ordinal_import.exe", ordinal_import()),
        ("forwarded.exe", forwarded()),
        ("missing_dll.exe", missing_dll()),
        ("corrupt_dir.exe", corrupt_dir()),
    ]
}

pub fn snapshots() -> Vec<(&'static str, &'static str)> {
    vec![
        ("kernel32.dll.json", r#"{"dll":"kernel32.dll","exports":[{"name":"ExitProcess","ordinal":10,"forwarder":null},{"name":"GetTickCount","ordinal":20,"forwarder":null}]}"#),
        ("kernel32-v2.dll.json", r#"{"dll":"kernel32.dll","exports":[{"name":"ExitProcess","ordinal":10,"forwarder":null}]}"#),
        ("ordonly.dll.json", r#"{"dll":"ordonly.dll","exports":[{"name":"OrdinalSeven","ordinal":7,"forwarder":null}]}"#),
        ("fwd.dll.json", r#"{"dll":"fwd.dll","exports":[{"name":"MiddleFunc","ordinal":1,"forwarder":"real.dll!RealFunc"}]}"#),
        ("real.dll.json", r#"{"dll":"real.dll","exports":[{"name":"RealFunc","ordinal":1,"forwarder":null}]}"#),
    ]
}
