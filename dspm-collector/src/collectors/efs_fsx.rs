use crate::collector_core::*;
use async_trait::async_trait;
use aws_types::region::Region;

pub struct EfsCollector;
#[async_trait]
impl Collector for EfsCollector {
    fn name(&self) -> &'static str { "efs" }
    async fn discover(&self, regions: &[String]) -> anyhow::Result<Vec<Asset>> {
        use aws_sdk_efs as efs;
        let mut out = vec![];
        for r in regions {
            let conf = aws_config::from_env().region(Region::new(r.clone())).load().await;
            let c = efs::Client::new(&conf);
            let fs = c.describe_file_systems().send().await?;
            for f in fs.file_systems().unwrap_or_default() {
                out.push(Asset{
                    id: f.file_system_id().unwrap_or_default().to_string(),
                    service: "efs".into(), kind: AssetKind::FileStore,
                    region: r.clone(), name: f.name().map(|s| s.to_string()),
                    uri: None,
                    size_bytes: f.size_in_bytes().and_then(|s| s.value()).map(|v| v as u64),
                    encrypted: f.encrypted(),
                    kms_key_id: f.kms_key_id().map(|s| s.to_string()),
                    tags: Default::default(),
                    metadata: Default::default(),
                });
            }
        }
        Ok(out)
    }
}

pub struct FsxCollector;
#[async_trait]
impl Collector for FsxCollector {
    fn name(&self) -> &'static str { "fsx" }
    async fn discover(&self, regions: &[String]) -> anyhow::Result<Vec<Asset>> {
        use aws_sdk_fsx as fsx;
        let mut out = vec![];
        for r in regions {
            let conf = aws_config::from_env().region(Region::new(r.clone())).load().await;
            let c = fsx::Client::new(&conf);
            let d = c.describe_file_systems().send().await?;
            for f in d.file_systems().unwrap_or_default() {
                out.push(Asset{
                    id: f.file_system_id().unwrap_or_default().to_string(),
                    service: "fsx".into(), kind: AssetKind::FileStore,
                    region: r.clone(), name: f.tags().and_then(|_| None), // 필요 시 name 태그 파싱
                    uri: None,
                    size_bytes: f.storage_capacity().map(|v| v as u64 * 1_000_000_000),
                    encrypted: f.kms_key_id().is_some(),
                    kms_key_id: f.kms_key_id().map(|s| s.to_string()),
                    tags: Default::default(),
                    metadata: Default::default(),
                });
            }
        }
        Ok(out)
    }
}