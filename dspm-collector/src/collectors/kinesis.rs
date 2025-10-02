use crate::collector_core::{Asset, AssetKind, Collector};
use anyhow::Result;
use async_trait::async_trait;
use aws_config::behavior_version::BehaviorVersion;
use aws_config::Region;
use aws_sdk_kinesis as kinesis;
use futures::TryStreamExt; 
use serde_json::json;
use std::collections::HashMap;

pub struct KinesisCollector;

impl KinesisCollector {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Collector for KinesisCollector {
    fn name(&self) -> &'static str {
        "kinesis"
    }

    async fn discover(&self, regions: &[String], _mock: bool) -> Result<Vec<Asset>> {
        let mut out: Vec<Asset> = Vec::new();

        for region in regions {
            let conf = aws_config::defaults(BehaviorVersion::latest())
                .region(Region::new(region.clone()))
                .load()
                .await;
            let client = kinesis::Client::new(&conf);

            // List streams (paginator)
            let mut paginator = client.list_streams().into_paginator().send();
            while let Some(page) = paginator.try_next().await? {
                let names = page.stream_names(); // &[String]
                for name in names {
                    let name_str = name.as_str();

                    // Describe summary
                    let desc = client
                        .describe_stream_summary()
                        .stream_name(name_str)
                        .send()
                        .await?;

                    let mut metadata: HashMap<String, serde_json::Value> = HashMap::new();
                    let mut tags: HashMap<String, String> = HashMap::new();

                    if let Some(sum) = desc.stream_description_summary() {
                        // open shard count: i32
                        let open_shards: i32 = sum.open_shard_count();
                        metadata.insert("open_shard_count".into(), json!(open_shards));

                        // stream mode
                        if let Some(m) = sum.stream_mode_details() {
                            match m.stream_mode() {
                                kinesis::types::StreamMode::OnDemand => {
                                    metadata.insert("stream_mode".into(), json!("ON_DEMAND"));
                                }
                                kinesis::types::StreamMode::Provisioned => {
                                    metadata.insert("stream_mode".into(), json!("PROVISIONED"));
                                }
                                _ => {}
                            }
                        }

                        // arn: &str 
                        let arn = sum.stream_arn();
                        metadata.insert("stream_arn".into(), json!(arn));

                        // Tags 조회
                        let tagres = client
                            .list_tags_for_stream()
                            .stream_name(name_str)
                            .send()
                            .await?;

                        for t in tagres.tags() {
                            let k = t.key().to_string();      // &str
                            if let Some(v) = t.value() {       // Option<&str>
                                tags.insert(k, v.to_string());
                            }
                        }

                        out.push(Asset {
                            id: arn.to_string(),
                            service: "kinesis".into(),
                            kind: AssetKind::ObjectStore, 
                            region: region.clone(),
                            name: Some(name.to_string()),
                            uri: Some(format!("kinesis://{}", name_str)),
                            size_bytes: None,
                            encrypted: None,
                            kms_key_id: None,
                            tags,
                            metadata,
                        });
                    }
                }
            }
        }

        Ok(out)
    }
}
