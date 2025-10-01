mod collector_core;
mod collectors; // re-export all collectors and call register_all()

use collector_core::{get_all};
use tokio::task;
use reqwest::Client;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let regions = aws_regions().await?;
    collectors::register_all(); // 각 모듈에서 collector_core::register 호출

    let client = Client::new();
    let mut all_assets = vec![];
    let tasks = get_all().into_iter().map(|c| {
        let regions = regions.clone();
        async move {
            match c.discover(&regions).await {
                Ok(mut v) => { println!("{} -> {} assets", c.name(), v.len()); Ok(v) }
                Err(e) => { eprintln!("{} failed: {e}", c.name()); Ok(vec![]) }
            }
        }
    });
    for res in futures::future::join_all(tasks).await {
        if let Ok(mut v) = res { all_assets.append(&mut v); }
    }

    // bulk post to analyzer
    client.post("http://localhost:8080/api/assets:bulk")
        .json(&all_assets)
        .send().await?
        .error_for_status()?;

    Ok(())
}

async fn aws_regions() -> anyhow::Result<Vec<String>> {
    use aws_config::meta::region::RegionProviderChain;
    use aws_sdk_ec2 as ec2;

    let conf = aws_config::load_from_env().await;
    let ec2c = ec2::Client::new(&conf);
    let out = ec2c.describe_regions().send().await?;
    let mut regions = vec![];
    for r in out.regions().unwrap_or_default() {
        if let Some(name) = r.region_name() { regions.push(name.to_string()); }
    }
    Ok(regions)
}