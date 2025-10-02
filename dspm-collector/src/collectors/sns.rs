use crate::collector_core::{Asset, AssetKind, Collector};
use anyhow::Result;
use async_trait::async_trait;
use aws_config::{BehaviorVersion, Region};
use aws_sdk_sns as sns;
use serde_json::json;
use std::collections::HashMap;

pub struct SnsCollector;

impl SnsCollector {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Collector for SnsCollector {
    fn name(&self) -> &'static str {
        "sns"
    }

    async fn discover(&self, regions: &[String], _mock: bool) -> Result<Vec<Asset>> {
        let mut out: Vec<Asset> = Vec::new();

        for region in regions {
            let conf = aws_config::defaults(BehaviorVersion::latest())
                .region(Region::new(region.clone()))
                .load()
                .await;
            let client = sns::Client::new(&conf);

            // List topics (paginator)
            let mut paginator = client.list_topics().into_paginator().send();
            while let Some(page) = paginator.next().await.transpose()? {
                let topics = page.topics(); // &[Topic]
                for t in topics {
                    let Some(arn) = t.topic_arn() else { continue; };

                    // Get attributes
                    let attrs_res = client.get_topic_attributes().topic_arn(arn).send().await?;
                    // In SNS v1: attributes() -> Option<&HashMap<String, String>>
                    let mut metadata: HashMap<String, serde_json::Value> = HashMap::new();
                    if let Some(attrs) = attrs_res.attributes() {
                        for (k, v) in attrs.iter() {
                            metadata.insert(k.clone(), json!(v));
                        }
                    }

                    // Tags (list_tags_for_resource)
                    let mut tags: HashMap<String, String> = HashMap::new();
                    let tag_res = client.list_tags_for_resource().resource_arn(arn).send().await?;
                    for tag in tag_res.tags() {
                        let k = tag.key();
                        let v = tag.value();
                        tags.insert(k.to_string(), v.to_string());
                    }

                    out.push(Asset {
                        id: arn.to_string(),
                        service: "sns".into(),
                        kind: AssetKind::ObjectStore,
                        region: region.clone(),
                        name: Some(arn.split(':').last().unwrap_or(arn).to_string()),
                        uri: Some(format!("arn://{}", arn)),
                        size_bytes: None,
                        encrypted: None,
                        kms_key_id: attrs_res
                            .attributes()
                            .and_then(|m| m.get("KmsMasterKeyId"))
                            .cloned(),
                        tags,
                        metadata,
                    });
                }
            }
        }

        Ok(out)
    }
}
