use crate::types::Asset;
use serde_json::json;

pub async fn discover_mock() -> Vec<Asset> {
    vec![
        Asset {
            kind: "bucket".into(),
            locator: "s3://demo-bucket".into(),
            name: "demo-bucket".into(),
            region: "ap-northeast-2".into(),
            bytes: None,
            meta: json!({
                "service": "s3",
                "public_access": false,
                "creation_date": "2025-09-29T12:00:00Z"
            }),
        },
        Asset {
            kind: "rds-instance".into(),
            locator: "rds://demo-db".into(),
            name: "demo-db".into(),
            region: "ap-northeast-2".into(),
            bytes: None,
            meta: json!({
                "engine": "postgres",
                "engine_version": "14.7",
                "class": "db.t3.micro",
                "status": "available",
                "service": "rds"
            }),
        },
        Asset {
            kind: "image".into(),
            locator: "ecr://demo-repo:latest".into(),
            name: "demo-repo:latest".into(),
            region: "ap-northeast-2".into(),
            bytes: Some(12345678),
            meta: json!({
                "service": "ecr",
                "tags": ["latest"],
                "digest": "sha256:deadbeef",
                "size_bytes": 12345678,
                "pushed_at": "2025-09-29T12:00:00Z"
            }),
        }
    ]
}
