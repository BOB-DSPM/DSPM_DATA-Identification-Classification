use anyhow::Result;
use aws_sdk_s3 as s3;
use serde_json::json;
use crate::types::Asset;

pub async fn discover_buckets(cfg: &aws_config::SdkConfig) -> Result<Vec<Asset>> {
    let client = s3::Client::new(cfg);
    let resp = client.list_buckets().send().await?;
    let mut out = Vec::<Asset>::new();

    for b in resp.buckets().iter() {
        let name = b.name().unwrap_or_default().to_string();
        let region = get_bucket_region(&client, &name).await.unwrap_or_else(|_| "unknown".into());
        let public_info = get_public_block(&client, &name).await.unwrap_or(serde_json::Value::Null);
        let meta = json!({
            "creation_date": b.creation_date().map(|d| d.to_string()),                     // ← 교체
            "service": "s3",
            "public_access": public_info
        });
        out.push(Asset{
            kind: "bucket".into(),
            locator: format!("s3://{}", name),
            name,
            region,
            bytes: None,
            meta
        });
    }
    Ok(out)
}

async fn get_bucket_region(client: &s3::Client, bucket: &str) -> Result<String> {
    let loc = client.get_bucket_location().bucket(bucket).send().await?;
    Ok(loc.location_constraint()
        .map(|r| r.as_str().to_string())
        .unwrap_or_else(|| "us-east-1".into()))
}

async fn get_public_block(client: &s3::Client, bucket: &str) -> Result<serde_json::Value> {
    let r = client.get_public_access_block().bucket(bucket).send().await;
    Ok(match r {
        Ok(v) => {
            let c = v.public_access_block_configuration().unwrap();
            json!({
                "block_public_acls": c.block_public_acls(),
                "ignore_public_acls": c.ignore_public_acls(),
                "block_public_policy": c.block_public_policy(),
                "restrict_public_buckets": c.restrict_public_buckets()
            })
        }
        Err(_) => serde_json::Value::Null, // 설정 없음 → 정보 없음
    })
}
