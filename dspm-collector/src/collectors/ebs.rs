use crate::collector_core::*;
use anyhow::Result;
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_types::region::Region;
use aws_sdk_ec2 as ec2;
use serde_json::json;
use std::collections::HashMap;

pub struct EbsCollector;
impl EbsCollector { pub fn new() -> Self { Self } }

#[async_trait]
impl Collector for EbsCollector {
    fn name(&self) -> &'static str { "ebs" }

    async fn discover(&self, regions: &[String], _mock: bool) -> Result<Vec<Asset>> {
        let mut out = Vec::new();

        for region in regions {
            let conf = aws_config::defaults(BehaviorVersion::latest())
                .region(Region::new(region.clone()))
                .load()
                .await;
            let client = ec2::Client::new(&conf);

            let mut next: Option<String> = None;
            loop {
                let resp = client.describe_volumes()
                    .set_next_token(next.clone())
                    .send().await?;

                for vol in resp.volumes() {
                    let mut tags_map = HashMap::new();
                    for t in vol.tags() {
                        if let (Some(k), Some(v)) = (t.key(), t.value()) {
                            tags_map.insert(k.to_string(), v.to_string());
                        }
                    }

                    let mut md = HashMap::new();
                    for a in vol.attachments() {
                        if let Some(iid) = a.instance_id() { md.insert("attached_instance".into(), json!(iid)); }
                        if let Some(dev) = a.device()      { md.insert("device".into(), json!(dev)); }
                        if let Some(st)  = a.state().map(|s| s.as_str()) {
                            md.insert("attachment_state".into(), json!(st));
                        }
                    }
                    if let Some(st) = vol.state().map(|s| s.as_str()) { md.insert("state".into(), json!(st)); }
                    if let Some(tp) = vol.volume_type().map(|v| v.as_str()) { md.insert("volume_type".into(), json!(tp)); }
                    if let Some(iops) = vol.iops() { md.insert("iops".into(), json!(iops)); }
                    if let Some(th) = vol.throughput() { md.insert("throughput".into(), json!(th)); }
                    if let Some(ma) = vol.multi_attach_enabled() { md.insert("multi_attach_enabled".into(), json!(ma)); }

                    let size_bytes = vol.size().map(|gib| gib as u64 * 1024 * 1024 * 1024);
                    let vol_id = vol.volume_id().unwrap_or("unknown");

                    out.push(Asset{
                        id: format!("arn:aws:ec2:{}:unknown:volume/{}", region, vol_id),
                        service: "ec2".into(),
                        kind: AssetKind::BlockStorage,
                        region: region.clone(),
                        name: Some(vol_id.to_string()),
                        uri: Some(format!("ec2://{}/volume/{}", region, vol_id)),
                        size_bytes,
                        encrypted: vol.encrypted(),                  // Option<bool>
                        kms_key_id: vol.kms_key_id().map(|s| s.to_string()),
                        tags: tags_map,
                        metadata: md,
                    });
                }

                next = resp.next_token().map(|s| s.to_string());
                if next.is_none() { break; }
            }
        }

        Ok(out)
    }
}
