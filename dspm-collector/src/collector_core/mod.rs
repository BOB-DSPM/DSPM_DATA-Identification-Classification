use anyhow::Result;
use async_trait::async_trait;
use once_cell::sync::Lazy;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// 표준화된 자산 종류
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum AssetKind {
    ObjectStore,   // S3 등
    Compute,       // EC2 인스턴스
    BlockStorage,  // EBS 볼륨
    Database,      // RDS
    NoSqlStore,    // DynamoDB
    MessageQueue,  // SQS 
}

/// 표준화된 Asset 스키마
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Asset {
    pub id: String,                 // 전역 ID (예: ARN)
    pub service: String,            // "s3" | "ec2" | ...
    pub kind: AssetKind,            // 위의 enum
    pub region: String,             // ap-northeast-2 등
    pub name: Option<String>,       // 리소스 이름
    pub uri: Option<String>,        // 위치 식별자 (예: s3://.., ec2://i-..)
    pub size_bytes: Option<u64>,    // 스토리지 용량 등
    pub encrypted: Option<bool>,    // 암호화 여부
    pub kms_key_id: Option<String>, // KMS 키(있다면)
    pub tags: HashMap<String, String>,
    pub metadata: HashMap<String, Value>,
}

#[async_trait]
pub trait Collector: Send + Sync {
    fn name(&self) -> &'static str;

    /// regions: ["ap-northeast-2", ...]
    /// mock: true면 외부 호출 없이 더미 반환
    async fn discover(&self, regions: &[String], mock: bool) -> Result<Vec<Asset>>;
}

/// ---- 전역 레지스트리: Arc<dyn Collector> 기반 ----
/// (Box 기반에서 Arc 기반으로 변경하여 E0277 제거)
pub static REGISTRY: Lazy<RwLock<Vec<Arc<dyn Collector>>>> =
    Lazy::new(|| RwLock::new(Vec::new()));

/// Collector 등록
pub fn register<C>(collector: C)
where
    C: Collector + 'static,
{
    let mut reg = REGISTRY.write().expect("registry write lock");
    reg.push(Arc::new(collector));
}

/// Collector 모두 가져오기
pub fn get_all() -> Vec<Arc<dyn Collector>> {
    let reg = REGISTRY.read().expect("registry read lock");
    reg.iter().cloned().collect()
}
