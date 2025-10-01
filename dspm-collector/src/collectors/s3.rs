use crate::collector_core::*;
use anyhow::Result;
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_s3 as s3;
use serde_json::json;
use std::collections::HashMap;

pub struct S3Collector;

impl S3Collector {
    pub fn new() -> Self { Self }
}

#[async_trait]
impl Collector for S3Collector {
    fn name(&self) -> &'static str { "s3" }

    async fn discover(&self, regions: &[String], mock: bool) -> Result<Vec<Asset>> {
        // Mock 모드: 빠른 로컬 테스트 용
        if mock {
            let mut md = HashMap::new();
            md.insert("public_blocked".into(), json!(true));
            return Ok(vec![Asset {
                id: "arn:aws:s3:::sample-bucket-mock".into(),
                service: "s3".into(),
                kind: AssetKind::ObjectStore,
                region: regions.get(0).cloned().unwrap_or_else(|| "ap-northeast-2".into()),
                name: Some("sample-bucket-mock".into()),
                uri: Some("s3://sample-bucket-mock/".into()),
                size_bytes: None,
                encrypted: Some(true),
                kms_key_id: None,
                tags: HashMap::from([("env".into(), "dev".into())]),
                metadata: md,
            }]);
        }

        // 실제 호출
        let conf = aws_config::load_defaults(BehaviorVersion::latest()).await;
        let client = s3::Client::new(&conf);

        let resp = client.list_buckets().send().await?;
        // 당신 SDK에선 &[Bucket] (Option 아님) 이므로 그대로 사용
        let buckets = resp.buckets();

        let mut out: Vec<Asset> = Vec::new();

        for b in buckets.iter() {
            let Some(name) = b.name() else { continue; };
            let name = name.to_string();

            // 리전 조회
            let region = match client.get_bucket_location().bucket(&name).send().await {
                Ok(loc) => {
                    loc.location_constraint()
                        .map(|v| v.as_str().to_string())
                        .unwrap_or_else(|| "us-east-1".to_string())
                }
                Err(_) => "unknown".to_string(),
            };

            // 리전 필터(옵션)
            if !regions.is_empty() && !regions.contains(&region) {
                continue;
            }

            // 암호화/KMS
            let (encrypted, kms_key_id) = match client.get_bucket_encryption().bucket(&name).send().await {
                Ok(enc) => {
                    if let Some(cfg) = enc.server_side_encryption_configuration() {
                        let rules = cfg.rules(); // &[ServerSideEncryptionRule]
                        let mut kms: Option<String> = None;
                        for r in rules {
                            if let Some(app) = r.apply_server_side_encryption_by_default() {
                                if let Some(k) = app.kms_master_key_id() {
                                    kms = Some(k.to_string());
                                    break;
                                }
                            }
                        }
                        (Some(!rules.is_empty()), kms)
                    } else {
                        (Some(false), None)
                    }
                }
                Err(_) => (None, None),
            };

            // 퍼블릭 접근 차단
            let public_blocked = match client.get_public_access_block().bucket(&name).send().await {
                Ok(pab) => {
                    if let Some(cfg) = pab.public_access_block_configuration() {
                        let acls = cfg.block_public_acls().unwrap_or(true);
                        let pol  = cfg.block_public_policy().unwrap_or(true);
                        Some(acls && pol)
                    } else { None }
                }
                Err(_) => None,
            };

            let mut metadata = HashMap::new();
            if let Some(pb) = public_blocked {
                metadata.insert("public_blocked".into(), json!(pb));
            }

            out.push(Asset {
                id: format!("arn:aws:s3:::{}", name),
                service: "s3".into(),
                kind: AssetKind::ObjectStore,
                region: region.clone(),
                name: Some(name.clone()),
                uri: Some(format!("s3://{name}/")),
                size_bytes: None,
                encrypted,
                kms_key_id,
                tags: HashMap::new(),
                metadata,
            });
        }

        Ok(out)
    }
}
