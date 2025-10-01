use crate::collector_core::*;
use async_trait::async_trait;
use aws_types::region::Region;

pub struct CwLogsCollector;

#[async_trait]
impl Collector for CwLogsCollector {
    fn name(&self) -> &'static str { "cloudwatch-logs" }

    async fn discover(&self, regions: &[String]) -> anyhow::Result<Vec<Asset>> {
        // MOCK_MODE 
        if std::env::var("MOCK_MODE").is_ok() {
            let data = tokio::fs::read_to_string("mocks/cloudwatch_describe_log_groups.json").await?;
            let parsed: serde_json::Value = serde_json::from_str(&data)?;
            let mut out = vec![];

            if let Some(arr) = parsed["logGroups"].as_array() {
                for g in arr {
                    out.push(Asset {
                        id: g["arn"].as_str().unwrap().to_string(),
                        service: "cloudwatch-logs".into(),
                        kind: AssetKind::LogStore,
                        region: "ap-northeast-2".into(),
                        name: g["logGroupName"].as_str().map(|s| s.to_string()),
                        uri: None,
                        size_bytes: None,
                        encrypted: Some(g["kmsKeyId"].is_string()),
                        kms_key_id: g["kmsKeyId"].as_str().map(|s| s.to_string()),
                        tags: Default::default(),
                        metadata: maplit::hashmap! {
                            "retention_days".into() => serde_json::json!(g["retentionInDays"].as_i64())
                        },
                    });
                }
            }
            return Ok(out);
        }

        // 실제 AWS 호출
        use aws_sdk_cloudwatchlogs as cwl;
        let mut out = vec![];
        for r in regions {
            let conf = aws_config::from_env().region(Region::new(r.clone())).load().await;
            let c = cwl::Client::new(&conf);
            let mut next = None;
            loop {
                let resp = c.describe_log_groups().set_next_token(next.take()).send().await?;
                for g in resp.log_groups().unwrap_or_default() {
                    out.push(Asset {
                        id: g.arn().unwrap_or_default().to_string(),
                        service: "cloudwatch-logs".into(),
                        kind: AssetKind::LogStore,
                        region: r.clone(),
                        name: g.log_group_name().map(|s| s.to_string()),
                        uri: None,
                        size_bytes: None,
                        encrypted: g.kms_key_id().is_some(),
                        kms_key_id: g.kms_key_id().map(|s| s.to_string()),
                        tags: Default::default(),
                        metadata: maplit::hashmap! {
                            "retention_days".into() => serde_json::json!(g.retention_in_days())
                        },
                    });
                }
                if resp.next_token().is_none() { break; }
                next = resp.next_token().map(|s| s.to_string());
            }
        }
        Ok(out)
    }
}
