use crate::collector_core::{Asset, AssetKind, Collector};
use anyhow::Result;
use async_trait::async_trait;
use aws_config::{BehaviorVersion, Region};
use aws_sdk_cloudwatchlogs as logs;
use serde_json::json;
use std::collections::HashMap;

pub struct CloudWatchLogsCollector;

impl CloudWatchLogsCollector {
    pub fn new() -> Self { Self }
}

#[async_trait]
impl Collector for CloudWatchLogsCollector {
    fn name(&self) -> &'static str { "cloudwatch-logs" }

    async fn discover(&self, regions: &[String], mock: bool) -> Result<Vec<Asset>> {
        if mock {
            let mut md = HashMap::new();
            md.insert("retention_days".into(), json!(14));
            md.insert("kms_key_id".into(), json!(null));
            return Ok(vec![Asset {
                id: "arn:aws:logs:ap-northeast-2:123456789012:log-group:/aws/lambda/demo:*".into(),
                service: "cloudwatch-logs".into(),
                kind: AssetKind::ObjectStore,
                region: "ap-northeast-2".into(),
                name: Some("/aws/lambda/demo".into()),
                uri: Some("logs://ap-northeast-2//aws/lambda/demo".into()),
                size_bytes: None,
                encrypted: Some(false),
                kms_key_id: None,
                tags: HashMap::new(),
                metadata: md,
            }]);
        }

        let mut out = Vec::new();
        for r in regions {
            let conf = aws_config::defaults(BehaviorVersion::latest())
                .region(Region::new(r.clone()))
                .load()
                .await;
            let client = logs::Client::new(&conf);

            // paginator.items() 를 쓰면 Option/슬라이스 차이로 인한 컴파일 이슈 회피 가능
            let mut stream = client
                .describe_log_groups()
                .into_paginator()
                .items()
                .send();

            while let Some(item) = stream.next().await {
                let lg = item?;
                let name = lg.log_group_name().unwrap_or_default().to_string();
                let kms = lg.kms_key_id().map(|s| s.to_string());
                let retention_days = lg.retention_in_days().map(|v| v as i64); // i32 → i64 or 그냥 i32도 OK

                let mut metadata = HashMap::new();
                if let Some(d) = retention_days { metadata.insert("retention_days".into(), json!(d)); }
                if let Some(ref k) = kms { metadata.insert("kms_key_id".into(), json!(k)); }

                out.push(Asset {
                    id: format!("arn:aws:logs:{}:unknown:log-group:{}:*", r, name), // account 미지정: 필요시 STS로 보강
                    service: "cloudwatch-logs".into(),
                    kind: AssetKind::ObjectStore,
                    region: r.clone(),
                    name: Some(name.clone()),
                    uri: Some(format!("logs://{}/{}", r, name)),
                    size_bytes: None,
                    encrypted: Some(kms.is_some()),
                    kms_key_id: kms,
                    tags: HashMap::new(), // CloudWatch Logs는 태그 API 별도(GetLogGroup) 필요, 초기엔 생략 가능
                    metadata,
                });
            }
        }

        Ok(out)
    }
}
