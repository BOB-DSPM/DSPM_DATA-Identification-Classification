use crate::collector_core::{Asset, AssetKind, Collector};
use anyhow::Result;
use async_trait::async_trait;
use aws_config::{BehaviorVersion, Region};
use aws_sdk_backup as backup;
use serde_json::json;
use std::collections::HashMap;

pub struct BackupCollector;

impl BackupCollector {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Collector for BackupCollector {
    fn name(&self) -> &'static str {
        "backup"
    }

    async fn discover(&self, regions: &[String], _mock: bool) -> Result<Vec<Asset>> {
        let mut out: Vec<Asset> = Vec::new();

        for region in regions {
            let conf = aws_config::defaults(BehaviorVersion::latest())
                .region(Region::new(region.clone()))
                .load()
                .await;
            let client = backup::Client::new(&conf);

            // Backup Vaults
            let mut paginator = client.list_backup_vaults().into_paginator().send();
            while let Some(page) = paginator.next().await.transpose()? {
                let vaults = page.backup_vault_list(); // &[BackupVaultListMember]
                for v in vaults {
                    let name = v.backup_vault_name().unwrap_or("unknown");
                    let arn = v.backup_vault_arn().unwrap_or("");
                    let kms_key_id = v.encryption_key_arn().map(|s| s.to_string());

                    let recovery_points: Option<u64> =
                        u64::try_from(v.number_of_recovery_points()).ok();

                    let mut metadata: HashMap<String, serde_json::Value> = HashMap::new();
                    if let Some(arn) = v.backup_vault_arn() {
                        metadata.insert("vault_arn".into(), json!(arn));
                    }
                    if let Some(creator) = v.creator_request_id() {
                        metadata.insert("creator_request_id".into(), json!(creator));
                    }
                    if let Some(cnt) = recovery_points {
                        metadata.insert("recovery_points".into(), json!(cnt));
                    }

                    out.push(Asset {
                        id: arn.to_string(),
                        service: "backup".into(),
                        kind: AssetKind::ObjectStore, 
                        region: region.clone(),
                        name: Some(name.to_string()),
                        uri: Some(format!("arn://{}", arn)),
                        size_bytes: None,
                        encrypted: Some(kms_key_id.is_some()),
                        kms_key_id,
                        tags: HashMap::new(),
                        metadata,
                    });
                }
            }
        }

        Ok(out)
    }
}
