use crate::collector_core::Asset;
use anyhow::{anyhow, Result};
use reqwest::Client;
use std::time::Duration;

pub async fn post_batches(
    endpoint: &str,
    assets: Vec<Asset>,
    batch_size: usize,
    batch_flush_ms: u64,
) -> Result<()> {
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    if assets.is_empty() {
        return Ok(());
    }

    let mut i = 0;
    while i < assets.len() {
        let j = (i + batch_size).min(assets.len());
        let batch = &assets[i..j];
        let resp = client
            .post(endpoint)
            .json(&batch)
            .send()
            .await
            .map_err(|e| anyhow!("POST send error: {e}"))?;

        if !resp.status().is_success() {
            let code = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("POST [{i}-{j}) failed: {code} - {body}"));
        }

        // flush 간격
        tokio::time::sleep(Duration::from_millis(batch_flush_ms)).await;
        i = j;
    }

    Ok(())
}
