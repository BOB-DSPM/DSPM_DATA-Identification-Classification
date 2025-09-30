mod types;
mod http;
mod utils;
mod s3;
mod rds;
mod ecr;
#[cfg(feature = "ec2")] mod ec2;
mod mock;

use anyhow::Result;
use types::{Asset, BulkPayload};
use utils::{chunked, list_enabled_regions, env_or};
use http::post_bulk;
use aws_config::BehaviorVersion;

const DEFAULT_ENDPOINT: &str = "http://localhost:8000/api/assets:bulk";
const DEFAULT_BULK: usize = 1000;

#[tokio::main]
async fn main() -> Result<()> {
    // ---- 설정 ----
    let endpoint = env_or("API_ENDPOINT", DEFAULT_ENDPOINT); 
    let source_id = env_or("SOURCE_ID", "default");
    let bulk_size: usize = env_or("ASSETS_BULK_SIZE", &DEFAULT_BULK.to_string())
        .parse().unwrap_or(DEFAULT_BULK);
    let use_mock = env_or("USE_MOCK", "false").to_lowercase() == "true";

    // ---- 수집 ----
    let mut assets: Vec<Asset>;

    if use_mock {
        // 모의 데이터만 업로드 (AWS 자격증명 불필요)
        assets = mock::discover_mock().await;
    } else {
        // 실제 AWS SDK 경로
        let cfg = aws_config::load_defaults(BehaviorVersion::latest()).await;

        // S3(글로벌)
        assets = s3::discover_buckets(&cfg).await.unwrap_or_default();

        // 리전 목록
        let regions = list_enabled_regions(&cfg).await.unwrap_or_default();

        // RDS/ECR/EC2(옵션) per region
        for r in &regions {
            if let Ok(mut v) = rds::discover_rds(&cfg, r).await { assets.append(&mut v); }
            if let Ok(mut v) = ecr::discover_ecr(&cfg, r).await { assets.append(&mut v); }
            #[cfg(feature = "ec2")]
            if let Ok(mut v) = ec2::discover_ec2(&cfg, r).await { assets.append(&mut v); }
        }
    }

    // ---- 청크 업로드 ----
    for batch in chunked(&assets, bulk_size) {
        let payload = BulkPayload { source_id: source_id.clone(), items: batch };
        post_bulk(&endpoint, &payload).await?;
    }

    println!("uploaded {} assets to {}", assets.len(), endpoint);
    Ok(())
}
