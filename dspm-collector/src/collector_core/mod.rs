use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use async_trait::async_trait;
use anyhow::Result;

// 표준 Asset 모델: camelCase 직렬화/역직렬화
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Asset {
    pub id: String,
    pub service: String,
    pub kind: AssetKind,
    pub region: String,
    pub name: Option<String>,
    pub uri: Option<String>,
    pub size_bytes: Option<i64>,
    pub encrypted: Option<bool>,
    pub kms_key_id: Option<String>,
    pub tags: HashMap<String, String>,
    pub metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AssetKind {
    ObjectStore,
    Database,
    Log,
    Queue,
    ComputeVolume,
}

// Collector 인터페이스
#[async_trait]
pub trait Collector: Send + Sync {
    fn name(&self) -> &'static str;
    async fn discover(&self, regions: &[String], mock: bool) -> Result<Vec<Asset>>;
}
