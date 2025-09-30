use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Asset {
    pub kind: String,          // "bucket" | "rds-instance" | "image" | "ec2-instance"
    pub locator: String,       // s3://bucket | rds://id | ecr://repo:tag | ec2://i-xxxx
    pub name: String,          // 표시용 이름
    pub region: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<i64>,
    #[serde(default)]
    pub meta: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BulkPayload {
    pub source_id: String,
    pub items: Vec<Asset>,
}
