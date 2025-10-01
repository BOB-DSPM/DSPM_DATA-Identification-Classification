use crate::collector_core::*;
use aws_sdk_s3 as s3;
use aws_types::region::Region;
use async_trait::async_trait;
use std::collections::HashMap;

pub struct S3Collector;

#[async_trait]
impl Collector for S3Collector {
    fn name(&self) -> &'static str { "s3" }

    async fn discover(&self, regions: &[String]) -> anyhow::Result<Vec<Asset>> {
        // MOCK_MODE 확인
        if std::env::var("MOCK_MODE").is_ok() {
            let data = tokio::fs::read_to_string("mocks/s3_list_buckets.json").await?;
            let parsed: serde_json::Value = serde_json::from_str(&data)?;

            let mut out_assets = vec![];
            if let Some(arr) = parsed["Buckets"].as_array() {
                for b in arr {
                    let name = b["Name"].as_str().unwrap();
                    out_assets.push(Asset {
                        id: format!("arn:aws:s3:::{}", name),
                        service: "s3".into(),
                        kind: AssetKind::ObjectStore,
                        region: "ap-northeast-2".into(), // mock 데이터는 리전 고정
                        name: Some(name.to_string()),
                        uri: Some(format!("s3://{}/", name)),
                        size_bytes: None,
                        encrypted: Some(true),
                        kms_key_id: None,
                        tags: HashMap::new(),
                        metadata: maplit::hashmap! {
                            "mock".into() => serde_json::json!(true)
                        },
                    });
                }
            }
            return Ok(out_assets);
        }

        // 실제 AWS SDK 호출 (기존 코드)
        let conf = aws_config::load_from_env().await;
        let client = s3::Client::new(&conf);
        let mut out_assets = vec![];

        let buckets = client.list_buckets().send().await?.buckets().unwrap_or_default().to_vec();
        for b in buckets {
            let name = b.name().unwrap().to_string();
            // 위치(리전)
            let loc = client.get_bucket_location().bucket(&name).send().await?;
            let region = loc.location_constraint().map(|v| v.as_str().to_string()).unwrap_or_else(|| "us-east-1".into());

            // 암호화
            let enc = client.get_bucket_encryption().bucket(&name).send().await.ok();
            let encrypted = enc.as_ref().and_then(|e| e.server_side_encryption_configuration()).is_some();

            // 퍼블릭 액세스 차단
            let pab = client.get_public_access_block().bucket(&name).send().await.ok();
            let is_public_blocked = pab.as_ref()
                .and_then(|v| v.public_access_block_configuration())
                .map(|c| c.block_public_acls().unwrap_or(true) && c.block_public_policy().unwrap_or(true))
                .unwrap_or(false);

            let mut meta = HashMap::new();
            meta.insert("public_blocked".into(), serde_json::json!(is_public_blocked));

            out_assets.push(Asset {
                id: format!("arn:aws:s3:::{}", name),
                service: "s3".into(),
                kind: AssetKind::ObjectStore,
                region,
                name: Some(name.clone()),
                uri: Some(format!("s3://{name}/")),
                size_bytes: None,
                encrypted: Some(encrypted),
                kms_key_id: None,
                tags: HashMap::new(),
                metadata: meta,
            });
        }
        Ok(out_assets)
    }
}
