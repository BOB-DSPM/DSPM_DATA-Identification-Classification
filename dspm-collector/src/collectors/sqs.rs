use crate::collector_core::{Asset, AssetKind, Collector};
use anyhow::Result;
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_sqs as sqs;
use serde_json::json;
use std::collections::HashMap;

pub struct SqsCollector;

impl SqsCollector {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Collector for SqsCollector {
    fn name(&self) -> &'static str {
        "sqs"
    }

    async fn discover(&self, regions: &[String], mock: bool) -> Result<Vec<Asset>> {
        if mock {
            let mut md = HashMap::new();
            md.insert("fifo".into(), json!(false));
            md.insert("visibility_timeout_seconds".into(), json!(30));
            return Ok(vec![Asset {
                id: "arn:aws:sqs:ap-northeast-2:123456789012:demo-queue".into(),
                service: "sqs".into(),
                kind: AssetKind::MessageQueue,
                region: regions
                    .get(0)
                    .cloned()
                    .unwrap_or_else(|| "ap-northeast-2".into()),
                name: Some("demo-queue".into()),
                uri: Some("https://sqs.ap-northeast-2.amazonaws.com/123456789012/demo-queue".into()),
                size_bytes: None,
                encrypted: Some(true),
                kms_key_id: Some("arn:aws:kms:ap-northeast-2:123456789012:key/mock".into()),
                tags: HashMap::from([("env".into(), "dev".into())]),
                metadata: md,
            }]);
        }

        let mut out = Vec::new();

        for region in regions {
            let conf = aws_config::defaults(BehaviorVersion::latest())
                .region(sqs::config::Region::new(region.clone()))
                .load()
                .await;

            let client = sqs::Client::new(&conf);

            // 1) 큐 목록: &[String]
            let list = client.list_queues().send().await?;
            let urls = list.queue_urls(); // &Vec<String>가 아니라 &[String] 임

            for url in urls {
                // 2) 속성 조회
                use aws_sdk_sqs::types::QueueAttributeName as Attr;
                let attrs_res = client
                    .get_queue_attributes()
                    .queue_url(url)
                    .attribute_names(Attr::All)
                    .send()
                    .await?;

                // Option<&HashMap<QueueAttributeName, String>>
                let mut attrs_map: HashMap<String, String> = HashMap::new();
                if let Some(a) = attrs_res.attributes() {
                    for (k, v) in a.iter() {
                        // k: QueueAttributeName → 문자열로 변환
                        attrs_map.insert(k.as_str().to_string(), v.clone());
                    }
                }

                // 3) 태그 조회: Option<&HashMap<String, String>>
                let mut tags: HashMap<String, String> = HashMap::new();
                if let Ok(tag_res) = client.list_queue_tags().queue_url(url).send().await {
                    if let Some(tmap) = tag_res.tags() {
                        for (k, v) in tmap.iter() {
                            tags.insert(k.clone(), v.clone());
                        }
                    }
                }

                // 이름 추출 (URL 마지막 세그먼트)
                let name = url.split('/').last().unwrap_or("unknown").to_string();

                // 암호화 / KMS
                let kms_key_id = attrs_map.get("KmsMasterKeyId").cloned();
                let managed_sse = attrs_map
                    .get("SqsManagedSseEnabled")
                    .and_then(|s| s.parse::<bool>().ok())
                    .unwrap_or(false);
                let encrypted = Some(kms_key_id.is_some() || managed_sse);

                // FIFO 여부
                let is_fifo = attrs_map
                    .get("FifoQueue")
                    .and_then(|s| s.parse::<bool>().ok())
                    .unwrap_or(false);

                // 기타 메타데이터
                let vis_timeout = attrs_map
                    .get("VisibilityTimeout")
                    .and_then(|s| s.parse::<i64>().ok());
                let delay_seconds = attrs_map
                    .get("DelaySeconds")
                    .and_then(|s| s.parse::<i64>().ok());
                let retention = attrs_map
                    .get("MessageRetentionPeriod")
                    .and_then(|s| s.parse::<i64>().ok());

                // ARN 있으면 쓰고, 없으면 URL 기반 ID
                let id = attrs_map
                    .get("QueueArn")
                    .cloned()
                    .unwrap_or_else(|| format!("sqs:{region}:{name}"));

                let mut metadata = HashMap::new();
                metadata.insert("fifo".into(), json!(is_fifo));
                if let Some(v) = vis_timeout {
                    metadata.insert("visibility_timeout_seconds".into(), json!(v));
                }
                if let Some(v) = delay_seconds {
                    metadata.insert("delay_seconds".into(), json!(v));
                }
                if let Some(v) = retention {
                    metadata.insert("message_retention_seconds".into(), json!(v));
                }

                out.push(Asset {
                    id,
                    service: "sqs".into(),
                    kind: AssetKind::MessageQueue,
                    region: region.clone(),
                    name: Some(name),
                    uri: Some(url.clone()),
                    size_bytes: None,
                    encrypted,
                    kms_key_id,
                    tags,
                    metadata,
                });
            }
        }

        Ok(out)
    }
}
