use anyhow::Result;
use aws_sdk_rds as rds;
use aws_types::region::Region;
use aws_config::BehaviorVersion;
use serde_json::json;
use crate::types::Asset;

pub async fn discover_rds(_cfg: &aws_config::SdkConfig, region: &str) -> Result<Vec<Asset>> {
    let regional_cfg = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new(region.to_string()))
        .load()
        .await;
    let client = rds::Client::new(&regional_cfg);

    let mut out = Vec::<Asset>::new();
    let mut marker = None;

    loop {
        let mut req = client.describe_db_instances();
        if let Some(m) = &marker { req = req.marker(m); }
        let resp = req.send().await?;

        for i in resp.db_instances().iter() {
            let id = i.db_instance_identifier().unwrap_or_default().to_string();
            let meta = json!({
                "engine": i.engine(),
                "engine_version": i.engine_version(),
                "class": i.db_instance_class(),
                "status": i.db_instance_status(),
                "multi_az": i.multi_az(),
                "encrypted": i.storage_encrypted(),
                "service": "rds"
            });
            out.push(Asset{
                kind: "rds-instance".into(),
                locator: format!("rds://{}", id),
                name: id,
                region: region.to_string(),
                bytes: None,
                meta
            });
        }
        marker = resp.marker().map(|s| s.to_string());
        if marker.is_none() { break; }
    }
    Ok(out)
}
