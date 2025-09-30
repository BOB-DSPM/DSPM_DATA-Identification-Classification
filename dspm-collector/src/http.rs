use crate::types::BulkPayload;
use anyhow::{Result, anyhow};
use std::time::Duration;

const CONNECT_TIMEOUT: u64 = 5;
const READ_TIMEOUT: u64 = 60;
const RETRIES: usize = 3;

pub async fn post_bulk(endpoint: &str, payload: &BulkPayload) -> Result<()> {
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT))
        .timeout(Duration::from_secs(READ_TIMEOUT))
        .build()?;

    let mut last = None;
    for attempt in 1..=RETRIES {
        let res = client.post(endpoint).json(payload).send().await;
        match res {
            Ok(r) if r.status().is_success() => return Ok(()),
            Ok(r) => last = Some(anyhow!("HTTP {} {}", r.status(), r.text().await.unwrap_or_default())),
            Err(e) => last = Some(anyhow!(e)),
        }
        tokio::time::sleep(Duration::from_millis(300 * attempt as u64)).await;
    }
    Err(last.unwrap_or_else(|| anyhow!("bulk post failed")))
}
