use crate::collector_core::{Asset, AssetKind, Collector};
use anyhow::Result;
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_cloudtrail as ct;
use serde_json::json;
use std::collections::HashMap;

pub struct CloudTrailCollector;

impl CloudTrailCollector {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Collector for CloudTrailCollector {
    fn name(&self) -> &'static str {
        "cloudtrail"
    }

    async fn discover(&self, regions: &[String], mock: bool) -> Result<Vec<Asset>> {
        if mock {
            let mut md = HashMap::new();
            md.insert("is_multi_region_trail".into(), json!(true));
            md.insert("has_insight_selectors".into(), json!(true));
            md.insert("s3_bucket".into(), json!("my-org-cloudtrail-logs"));
            return Ok(vec![Asset {
                id: "arn:aws:cloudtrail:ap-northeast-2:123456789012:trail/OrgTrailMock".into(),
                service: "cloudtrail".into(),
                kind: AssetKind::ObjectStore,
                region: regions.get(0).cloned().unwrap_or_else(|| "ap-northeast-2".into()),
                name: Some("OrgTrailMock".into()),
                uri: Some("cloudtrail://OrgTrailMock".into()),
                size_bytes: None,
                encrypted: Some(true),
                kms_key_id: Some("arn:aws:kms:ap-northeast-2:123456789012:key/mock-kms".into()),
                tags: HashMap::new(),
                metadata: md,
            }]);
        }

        let mut out = Vec::new();

        for region in regions {
            let conf = aws_config::defaults(BehaviorVersion::latest())
                .region(aws_sdk_cloudtrail::config::Region::new(region.clone()))
                .load()
                .await;
            let client = ct::Client::new(&conf);

            let resp = client
                .describe_trails()
                .include_shadow_trails(true)
                .send()
                .await?;

            let trails = resp.trail_list();

            for t in trails.iter() {
                let name = t.name().unwrap_or("unknown").to_string();
                let arn = t.trail_arn().unwrap_or("").to_string();

                let s3_bucket = t.s3_bucket_name().map(|s| s.to_string());
                let s3_prefix = t.s3_key_prefix().map(|s| s.to_string());
                let cw_logs_group_arn = t.cloud_watch_logs_log_group_arn().map(|s| s.to_string());
                let cw_logs_role_arn = t.cloud_watch_logs_role_arn().map(|s| s.to_string());

                let kms_key_id = t.kms_key_id().map(|s| s.to_string());
                let is_multi_region = t.is_multi_region_trail().unwrap_or(false);
                let log_file_validation = t.log_file_validation_enabled().unwrap_or(true);
                let is_org_trail = t.is_organization_trail().unwrap_or(false);
                let home_region = t.home_region().unwrap_or(region).to_string();

                // Insight selectors 
                let mut has_insight = None;
                if let Some(trail_name) = t.name() {
                    if let Ok(insights) = client
                        .get_insight_selectors()
                        .trail_name(trail_name)
                        .send()
                        .await
                    {
                        let cnt = insights.insight_selectors().len();
                        has_insight = Some(cnt > 0);
                    }
                }

                let mut metadata = HashMap::new();
                if let Some(b) = s3_bucket.as_ref() {
                    metadata.insert("s3_bucket".into(), json!(b));
                }
                if let Some(p) = s3_prefix.as_ref() {
                    metadata.insert("s3_prefix".into(), json!(p));
                }
                if let Some(g) = cw_logs_group_arn.as_ref() {
                    metadata.insert("cw_logs_group_arn".into(), json!(g));
                }
                if let Some(r) = cw_logs_role_arn.as_ref() {
                    metadata.insert("cw_logs_role_arn".into(), json!(r));
                }
                metadata.insert("is_multi_region_trail".into(), json!(is_multi_region));
                metadata.insert("log_file_validation".into(), json!(log_file_validation));
                metadata.insert("is_organization_trail".into(), json!(is_org_trail));
                metadata.insert("home_region".into(), json!(home_region));
                if let Some(h) = has_insight {
                    metadata.insert("has_insight_selectors".into(), json!(h));
                }

                out.push(Asset {
                    id: if !arn.is_empty() {
                        arn
                    } else {
                        format!("cloudtrail:{region}:{name}")
                    },
                    service: "cloudtrail".into(),
                    kind: AssetKind::ObjectStore,
                    region: region.clone(),
                    name: Some(name),
                    uri: Some(format!("cloudtrail://{}", t.trail_arn().unwrap_or("unknown"))),
                    size_bytes: None,
                    encrypted: kms_key_id.as_ref().map(|_| true),
                    kms_key_id,
                    tags: HashMap::new(),
                    metadata,
                });
            }
        }

        Ok(out)
    }
}
