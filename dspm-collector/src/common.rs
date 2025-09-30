use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct MetaPayload {
    pub source_id: String,   // 예: "aws"
    pub object_type: String, // "S3_OBJECT" / "RDS_INSTANCE" / "ECR_IMAGE" 등
    pub locator: String,     // aws-s3://{account}/{region}/{bucket}/{key}
    pub bytes: i64,
    pub extra: serde_json::Value,
}
