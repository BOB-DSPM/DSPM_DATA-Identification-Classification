use crate::collector_core::*;
use async_trait::async_trait;
use aws_types::region::Region;

pub struct DynamoCollector;

#[async_trait]
impl Collector for DynamoCollector {
    fn name(&self) -> &'static str { "dynamodb" }

    async fn discover(&self, regions: &[String]) -> anyhow::Result<Vec<Asset>> {
        // MOCK_MODE
        if std::env::var("MOCK_MODE").is_ok() {
            let data = tokio::fs::read_to_string("mocks/dynamodb_list_tables.json").await?;
            let parsed: serde_json::Value = serde_json::from_str(&data)?;
            let mut out = vec![];

            if let Some(arr) = parsed["TableNames"].as_array() {
                for t in arr {
                    let name = t.as_str().unwrap();
                    out.push(Asset {
                        id: format!("arn:aws:dynamodb:ap-northeast-2:111111111111:table/{}", name),
                        service: "dynamodb".into(),
                        kind: AssetKind::NoSQL,
                        region: "ap-northeast-2".into(),
                        name: Some(name.to_string()),
                        uri: None,
                        size_bytes: None,
                        encrypted: Some(true),
                        kms_key_id: Some("alias/aws/dynamodb".into()),
                        tags: Default::default(),
                        metadata: Default::default(),
                    });
                }
            }
            return Ok(out);
        }

        // 실제 AWS 호출
        use aws_sdk_dynamodb as ddb;
        let mut out = vec![];
        for r in regions {
            let conf = aws_config::from_env().region(Region::new(r.clone())).load().await;
            let c = ddb::Client::new(&conf);
            let tables = c.list_tables().send().await?;
            for t in tables.table_names().unwrap_or_default() {
                out.push(Asset {
                    id: format!("arn:aws:dynamodb:{}::table/{}", r, t),
                    service: "dynamodb".into(),
                    kind: AssetKind::NoSQL,
                    region: r.clone(),
                    name: Some(t.to_string()),
                    uri: None,
                    size_bytes: None,
                    encrypted: None,
                    kms_key_id: None,
                    tags: Default::default(),
                    metadata: Default::default(),
                });
            }
        }
        Ok(out)
    }
}
