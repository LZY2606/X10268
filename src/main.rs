mod ids;
mod pe_builder;
mod pe_parser;
mod loader;

fn main() {
    let pe = pe_builder::build_pe();
    let facts = pe_parser::parse_pe(&pe);
    let (snaps, diags) = loader::parse_snapshots(&pe_builder::exports_v1_json(), "src/exports-v1").unwrap();
    let view = loader::derive(&facts, &pe, pe_builder::IMAGE_BASE, &snaps);
    println!("sections={} relocs={} imports={} diags={} snapdiags={}",
        view.sections.len(), view.reloc_patches.len(), view.imports.len(),
        facts.diagnostics.len(), diags.len());
    for p in &view.reloc_patches {
        println!("  {} {:?} rva=0x{:X} -> {}", p.reloc_id, p.type_name, p.target_rva, p.status);
    }
    for i in &view.imports {
        println!("  {} {} ord={:?} -> {} chain={:?}", i.import_id, i.dll_name, i.ordinal, i.status, i.forward_chain);
    }
    for d in &facts.diagnostics {
        println!("  DIAG {} {}", d.code, d.message);
    }
}
