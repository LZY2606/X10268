mod archive;
mod db;
mod engine;
mod fixture;
mod models;
mod server;
mod web;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut addr = "127.0.0.1:5369".to_string();
    let mut database = "pe-loader-evidence.sqlite3".to_string();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => {
                i += 1;
                addr = args.get(i).cloned().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "--addr requires a value"))?;
            }
            "--db" => {
                i += 1;
                database = args.get(i).cloned().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "--db requires a value"))?;
            }
            other => {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("unknown argument: {other}")));
            }
        }
        i += 1;
    }
    server::serve(addr, database).await
}
