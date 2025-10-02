use crate::collector_core::*;
use anyhow::Result;
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_rds as rds;
use serde_json::json;
use std::collections::HashMap;

pub struct RdsCollector;
impl RdsCollector { pub fn new() -> Self { Self } }

#[async_trait]
impl Collector for RdsCollector {
    fn name(&self) -> &'static str { "rds" }

    async fn discover(&self, regions: &[String], _mock: bool) -> Result<Vec<Asset>> {
      let base = aws_config::load_defaults(BehaviorVersion::latest()).await;
      let mut out = Vec::new();

      for region in regions {
        let conf = aws_config::from_env()
          .region(aws_types::region::Region::new(region.clone()))
          .load().await;
        let client = rds::Client::new(&conf);

        let mut marker: Option<String> = None;
        loop {
          let resp = client.describe_db_instances()
            .set_marker(marker.clone())
            .send().await?;

          for db in resp.db_instances() { // <-- &[DbInstance]
            let id   = db.db_instance_identifier().unwrap_or("unknown").to_string();
            let arn  = db.db_instance_arn().unwrap_or_default().to_string();
            let eng  = db.engine().unwrap_or_default();
            let enc  = db.storage_encrypted();           // Option<bool>
            let kms  = db.kms_key_id().map(|s| s.to_string());
            let name = Some(id.clone());

            let mut md: HashMap<String, serde_json::Value> = HashMap::new();
            if let Some(klass) = db.db_instance_class() { md.insert("class".into(), json!(klass)); }
            if let Some(st)    = db.db_instance_status() { md.insert("status".into(), json!(st)); }
            if let Some(ep)    = db.endpoint() {
              if let Some(addr) = ep.address() { md.insert("endpoint".into(), json!(addr)); }
              if let Some(port) = ep.port()    { md.insert("port".into(), json!(port)); }
            }
            md.insert("engine".into(), json!(eng));

            out.push(Asset{
              id: if !arn.is_empty() { arn } else { format!("arn:aws:rds:{}:unknown:db:{}", region, id) },
              service: "rds".into(),
              kind: AssetKind::ObjectStore, 
              region: region.clone(),
              name,
              uri: Some(format!("rds://{}/{}", region, id)),
              size_bytes: None,
              encrypted: enc,
              kms_key_id: kms,
              tags: HashMap::new(), 
              metadata: md
            });
          }

          marker = resp.marker().map(|s| s.to_string());
          if marker.is_none() { break; }
        }
      }

      Ok(out)
    }
}
