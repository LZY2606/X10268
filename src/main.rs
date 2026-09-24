//! PE 装载语义/重定位证据台 —— 完全本地，无外部网络依赖。
//! 启动：cargo run -- --addr 127.0.0.1:5369

mod app;
mod db;
mod engine;
mod fixture;
mod model;
mod pe;
mod service;
mod state;

use std::net::SocketAddr;

#[derive(Debug)]
struct Args { addr: SocketAddr, db: String, auto_seed: bool }

fn parse_args() -> Args {
    let mut addr: SocketAddr = "127.0.0.1:5369".parse().unwrap();
    let mut db = "pe_loader_bench.sqlite3".to_string();
    let mut auto_seed = true;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--addr" => addr = it.next().expect("--addr 需要值").parse().expect("地址格式错误"),
            "--db" => db = it.next().expect("--db 需要值"),
            "--no-seed" => auto_seed = false,
            "-h" | "--help" => {
                println!("用法: pe_loader_bench --addr 127.0.0.1:5369 [--db PATH] [--no-seed]");
                std::process::exit(0);
            }
            other => panic!("未知参数: {other}"),
        }
    }
    Args { addr, db, auto_seed }
}

#[tokio::main]
async fn main() {
    let args = parse_args();
    let mut conn = db::open(&args.db).expect("打开数据库失败");
    if args.auto_seed {
        service::seed_fixture(&mut conn).expect("装载内置案例失败");
        service::seed_alt_conflict(&mut conn).expect("建立冲突分支失败");
    }
    let app = app::router(conn);
    let listener = tokio::net::TcpListener::bind(args.addr).await.expect("绑定地址失败");
    eprintln!("PE 装载证据台已启动: http://{}", args.addr);
    axum::serve(listener, app).await.expect("server error");
}

pub fn build_test_router() -> axum::Router {
    let conn = db::open_in_memory().unwrap();
    app::router(conn)
}
