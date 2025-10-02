use crate::collector_core::*;
use anyhow::Result;
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_types::region::Region;
use aws_sdk_ecr as ecr;
use serde_json::json;
use std::collections::HashMap;

pub struct EcrCollector;
impl EcrCollector { pub fn new() -> Self { Self } }

#[async_trait]
impl Collector for EcrCollector {
    fn name(&self) -> &'static str { "ecr" }

    async fn discover(&self, regions: &[String], _mock: bool) -> Result<Vec<Asset>> {
        // 기본 로더 (지역별로 다시 load해서 사용)
        let _base = aws_config::load_defaults(BehaviorVersion::latest()).await;

        let mut out = Vec::new();

        for region in regions {
            let conf = aws_config::defaults(BehaviorVersion::latest())
                .region(Region::new(region.clone()))
                .load()
                .await;
            let client = ecr::Client::new(&conf);

            let mut next: Option<String> = None;
            loop {
                let resp = client
                    .describe_repositories()
                    .set_next_token(next.clone())
                    .send()
                    .await?;

                for repo in resp.repositories() {
                    let Some(name) = repo.repository_name() else { continue; };
                    let arn = repo.repository_arn().unwrap_or_default().to_string();

                    // 메타데이터
                    let mut md = HashMap::new();
                    if let Some(cfg) = repo.image_scanning_configuration() {
                        // scan_on_push() -> bool
                        let s = cfg.scan_on_push();
                        md.insert("scan_on_push".into(), json!(s));
                    }

                    // 태그
                    let mut tags = HashMap::new();
                    if !arn.is_empty() {
                        if let Ok(tagres) = client
                            .list_tags_for_resource()
                            .resource_arn(&arn)
                            .send()
                            .await
                        {
                            for t in tagres.tags() {
                                // key(), value() -> &str
                                let k = t.key();
                                let v = t.value();
                                tags.insert(k.to_string(), v.to_string());
                            }
                        }
                    }

                    out.push(Asset {
                        id: arn.clone(),
                        service: "ecr".into(),
                        kind: AssetKind::ObjectStore,
                        region: region.clone(),
                        name: Some(name.to_string()),
                        uri: Some(format!("ecr://{}/{}", region, name)),
                        size_bytes: None,
                        encrypted: None,       // 레지스트리 암호화 API는 SDK 버전에 따라 달라 생략
                        kms_key_id: None,
                        tags,
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
