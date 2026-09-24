# PE Loader Evidence Bench

Completely local Rust/Axum/SQLite evidence workspace for PE section mapping, base relocations, import binding, and branchable review decisions.

## Validate

```sh
cargo build --all-targets
cargo test --all-targets
```

## Run

```sh
cargo run -- --addr 127.0.0.1:5369
```

Open <http://127.0.0.1:5369>. The bundled offline PE64 case is seeded automatically into `pe-loader-evidence.sqlite3`.
