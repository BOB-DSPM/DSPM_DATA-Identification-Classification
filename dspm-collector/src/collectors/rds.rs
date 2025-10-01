use crate::collector_core::*;
use async_trait::async_trait;
use aws_types::region::Region;

pub struct RdsCollector;

#[async_trait]
impl Collector for RdsCollector {
    fn name(&self) -> &'static str { "rds" }

    async fn discover(&self, regions: &[String]) -> anyhow::Result<Vec<Asset>> {
        // MOCK_MODE
        if std::env::var("MOCK_MODE").is_ok() {
            let data = tokio::fs::read_to_string("mocks/rds_describe_dbinstances.json").await?;
            let parsed: serde_json::Value = serde_json::from_str(&data)?;
            let mut out = vec![];

            if let Some(arr) = parsed["DBInstances"].as_array() {
                for db in arr {
                    out.push(Asset {
                        id: db["DBInstanceArn"].as_str().unwrap_or("mock-arn").to_string(),
                        service: "rds".into(),
                        kind: AssetKind::Database,
                        region: "ap-northeast-2".into(),
                        name: db["DBInstanceIdentifier"].as_str().map(|s| s.to_string()),
                        uri: db["Endpoint"]["Address"].as_str().map(|a| {
                            format!("{}:{}", a, db["Endpoint"]["Port"].as_i64().unwrap_or(5432))
                        }),
                        size_bytes: None,
                        encrypted: db["StorageEncrypted"].as_bool(),
                        kms_key_id: None,
                        tags: Default::default(),
                        metadata: maplit::hashmap! {
                            "engine".into() => serde_json::json!(db["Engine"].as_str()),
                            "engine_version".into() => serde_json::json!(db["EngineVersion"].as_str()),
                            "allocated_storage_gb".into() => serde_json::json!(db["AllocatedStorage"].as_i64())
                        },
                    });
                }
            }
            return Ok(out);
        }

        // 실제 AWS 호출
        use aws_sdk_rds as rds;
        let mut out = vec![];
        for r in regions {
            let conf = aws_config::from_env().region(Region::new(r.clone())).load().await;
            let c = rds::Client::new(&conf);
            let dbs = c.describe_db_instances().send().await?;
            for db in dbs.db_instances().unwrap_or_default() {
                out.push(Asset {
                    id: db.db_instance_arn().unwrap_or_default().to_string(),
                    service: "rds".into(),
                    kind: AssetKind::Database,
                    region: r.clone(),
                    name: db.db_instance_identifier().map(|s| s.to_string()),
                    uri: db.endpoint().and_then(|e| {
                        e.address().map(|a| format!("{}:{}", a, e.port().unwrap_or(5432)))
                    }),
                    size_bytes: None,
                    encrypted: db.storage_encrypted(),
                    kms_key_id: db.kms_key_id().map(|s| s.to_string()),
                    tags: Default::default(),
                    metadata: maplit::hashmap! {
                        "engine".into() => serde_json::json!(db.engine()),
                        "engine_version".into() => serde_json::json!(db.engine_version()),
                        "storage".into() => serde_json::json!(db.allocated_storage())
                    },
                });
            }
        }
        Ok(out)
    }
}
