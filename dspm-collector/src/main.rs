mod collector_core;
mod collectors;
mod out;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use collectors::{build_collectors, ServiceKind};
use out::{http::post_batches, emit_stdout, OutMode};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum OutModeArg {
    Stdout,
    Http,
}

impl From<OutModeArg> for OutMode {
    fn from(v: OutModeArg) -> Self {
        match v {
            OutModeArg::Stdout => OutMode::Stdout,
            OutModeArg::Http => OutMode::Http,
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "dspm-collector", version, author, about = "DSPM asset collector")]
struct Opts {
    /// 수집할 서비스 (콤마 구분): s3
    #[arg(long)]
    services: String,

    /// 리전 목록 (콤마 구분): ap-northeast-2,us-east-1 ...
    #[arg(long)]
    regions: String,

    /// mock 모드 (플래그가 있으면 true)
    #[arg(long, default_value_t = false)]
    mock: bool,

    /// 출력 모드: stdout | http
    #[arg(long = "out-mode", value_enum, default_value_t = OutModeArg::Stdout)]
    out_mode: OutModeArg,

    /// out-mode가 http일 때 전송할 엔드포인트
    #[arg(long, default_value = "http://localhost:8080/api/assets/bulk")]
    endpoint: String,

    /// 배치 크기
    #[arg(long = "batch-size", default_value_t = 200)]
    batch_size: usize,

    /// 배치 flush 간격(ms)
    #[arg(long = "batch-flush-ms", default_value_t = 800)]
    batch_flush_ms: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    // 로그(선택)
    tracing_subscriber::fmt().with_env_filter("info").init();

    let opts = Opts::parse();

    let services = ServiceKind::parse_list(&opts.services);
    let regions: Vec<String> = opts
        .regions
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let collectors = build_collectors(&services)?;
    let mut all_assets = Vec::new();

    for c in collectors {
        match c.discover(&regions, opts.mock).await {
            Ok(mut list) => {
                all_assets.append(&mut list);
            }
            Err(e) => {
                eprintln!("collector {} failed: {e}", c.name());
            }
        }
    }

    match OutMode::from(opts.out_mode) {
        OutMode::Stdout => emit_stdout(&all_assets).await?,
        OutMode::Http => {
            println!("discovered assets = {}", all_assets.len());
            post_batches(&opts.endpoint, all_assets, opts.batch_size, opts.batch_flush_ms).await?;
            println!("POST done");
        }
    }

    Ok(())
}
