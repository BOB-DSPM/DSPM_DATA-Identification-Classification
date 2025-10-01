use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AssetKind {
    ObjectStore, FileStore, BlockStore,
    Database, DataWarehouse, NoSQL, GraphDB, TimeSeries, Ledger,
    LogStore, Stream, Queue, Topic, EventBus, Search,
    MLArtifact, ETL, Backup, Secrets, Params, Registry, Docs, Other,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Asset {
    pub id: String,                 // 글로벌 유니크 키(arn or composed)
    pub service: String,            // "s3", "rds", ...
    pub kind: AssetKind,
    pub region: String,
    pub name: Option<String>,
    pub uri: Option<String>,        // s3://bucket/prefix, opensearch endpoint, rds arn 등
    pub size_bytes: Option<u64>,    // 가능할 때
    pub encrypted: Option<bool>,
    pub kms_key_id: Option<String>,
    pub tags: HashMap<String, String>,
    pub metadata: HashMap<String, serde_json::Value>, // 서비스 고유 메타
}

#[async_trait]
pub trait Collector: Send + Sync {
    fn name(&self) -> &'static str;
    async fn discover(&self, regions: &[String]) -> anyhow::Result<Vec<Asset>>;
}

// simple registry
use once_cell::sync::Lazy;
use std::sync::RwLock;

static REGISTRY: Lazy<RwLock<Vec<Box<dyn Collector>>>> = Lazy::new(|| RwLock::new(vec![]));

pub fn register(c: Box<dyn Collector>) { REGISTRY.write().unwrap().push(c); }
pub fn get_all() -> Vec<Box<dyn Collector>> {
    REGISTRY.read().unwrap().iter().map(|c| c.as_ref()).cloned().collect()
}