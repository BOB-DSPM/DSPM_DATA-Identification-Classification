use crate::collector_core::*; use async_trait::async_trait; use aws_types::region::Region;

pub struct EcrCollector;
#[async_trait]
impl Collector for EcrCollector {
    fn name(&self) -> &'static str { "ecr" }
    async fn discover(&self, regions: &[String]) -> anyhow::Result<Vec<Asset>> {
        use aws_sdk_ecr as ecr;
        let mut out = vec![];
        for r in regions {
            let conf = aws_config::from_env().region(Region::new(r.clone())).load().await;
            let c = ecr::Client::new(&conf);
            let repos = c.describe_repositories().send().await?;
            for repo in repos.repositories().unwrap_or_default() {
                out.push(Asset{
                    id: repo.repository_arn().unwrap_or_default().to_string(),
                    service: "ecr".into(), kind: AssetKind::Registry,
                    region: r.clone(), name: repo.repository_name().map(|s| s.to_string()),
                    uri: repo.repository_uri().map(|s| s.to_string()),
                    size_bytes: None, encrypted: None, kms_key_id: None,
                    tags: Default::default(), metadata: Default::default(),
                });
            }
        }
        Ok(out)
    }
}

pub struct Ec2EbsCollector; // describe_volumes/describe_snapshots → BlockStore
pub struct AwsBackupCollector; // list_backup_vaults/list_recovery_points_by_vault → Backup
pub struct SageMakerCollector; // list_models/list_training_jobs → S3 경로(artifact) 메타만 추출