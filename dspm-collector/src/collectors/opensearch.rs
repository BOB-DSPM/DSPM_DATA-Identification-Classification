use crate::collector_core::{Asset, AssetKind, Collector};
use anyhow::Result;
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_opensearch as opensearch;
use aws_types::region::Region;
use serde_json::json;
use std::collections::HashMap;

pub struct OpenSearchCollector;

impl OpenSearchCollector {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Collector for OpenSearchCollector {
    fn name(&self) -> &'static str {
        "opensearch"
    }

    async fn discover(&self, regions: &[String], mock: bool) -> Result<Vec<Asset>> {
        if mock {
            let mut md = HashMap::new();
            md.insert("engine".into(), json!("OpenSearch_2.13"));
            return Ok(vec![Asset {
                id: "arn:aws:es:ap-northeast-2:111122223333:domain/mock-domain".into(),
                service: "opensearch".into(),
                kind: AssetKind::ObjectStore, 
                region: regions
                    .get(0)
                    .cloned()
                    .unwrap_or_else(|| "ap-northeast-2".to_string()),
                name: Some("mock-domain".into()),
                uri: Some("https://mock-domain.ap-northeast-2.es.amazonaws.com".into()),
                size_bytes: None,
                encrypted: Some(true),
                kms_key_id: None,
                tags: HashMap::from([("env".into(), "dev".into())]),
                metadata: md,
            }]);
        }

        let mut out = Vec::new();

        for region in regions {
            let conf = aws_config::defaults(BehaviorVersion::latest())
                .region(Region::new(region.clone()))
                .load()
                .await;
            let client = opensearch::Client::new(&conf);

            let list = client.list_domain_names().send().await?;
            for info in list.domain_names().iter() {
                let domain_name = info.domain_name().unwrap_or("unknown"); 
                let desc = client
                    .describe_domain()
                    .domain_name(domain_name)
                    .send()
                    .await?
                    .domain_status
                    .expect("domain_status missing");

                let arn = desc.arn().to_string();
                let engine =
                    desc.engine_version().unwrap_or("unknown").to_string();
                let endpoint = desc.endpoint().map(|s| s.to_string());
                let kms_key = desc
                    .encryption_at_rest_options()
                    .and_then(|e| e.kms_key_id().map(|s| s.to_string()));
                let encrypted = desc
                    .encryption_at_rest_options()
                    .map(|e| e.enabled().unwrap_or(true)); 

                let mut tags_map: HashMap<String, String> = HashMap::new();
                if !arn.is_empty() {
                    let tagres = client.list_tags().arn(arn.clone()).send().await?;
                    for t in tagres.tag_list().iter() {
                        let k = t.key().to_string();
                        let v = t.value().to_string();
                        if !k.is_empty() {
                            tags_map.insert(k, v);
                        }
                    }
                }

                let mut metadata = HashMap::new();
                metadata.insert("engine".into(), json!(engine));
                if let Some(ep) = &endpoint {
                    metadata.insert("endpoint".into(), json!(ep));
                }

                out.push(Asset {
                    id: arn, 
                    service: "opensearch".into(),
                    kind: AssetKind::ObjectStore, 
                    region: region.clone(),
                    name: Some(domain_name.to_string()),
                    uri: endpoint,
                    size_bytes: None,               
                    encrypted,                      
                    kms_key_id: kms_key,          
                    tags: tags_map,
                    metadata,
                });
            }
        }

        Ok(out)
    }
}
