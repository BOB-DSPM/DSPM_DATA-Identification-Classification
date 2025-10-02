use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_ec2 as ec2;
use aws_sdk_sts as sts;
use aws_types::region::Region;
use serde_json::{json, Map as JsonMap, Value};
use std::collections::HashMap;

use crate::collector_core::{Asset, AssetKind, Collector};

pub struct EC2Collector;

impl EC2Collector {
    pub fn new() -> Self {
        Self
    }

    fn tags_to_hashmap(tags: &[ec2::types::Tag]) -> HashMap<String, String> {
        tags.iter()
            .filter_map(|t| {
                let k = t.key()?;
                let v = t.value()?;
                Some((k.to_string(), v.to_string()))
            })
            .collect()
    }

    fn jsonmap_into_hashmap(m: JsonMap<String, Value>) -> HashMap<String, Value> {
        m.into_iter().collect()
    }

    async fn get_account_id() -> anyhow::Result<String> {
        // deprecated 대체: load_defaults(BehaviorVersion::latest())
        let conf = aws_config::load_defaults(BehaviorVersion::latest()).await;
        let client = sts::Client::new(&conf);
        let who = client.get_caller_identity().send().await?;
        Ok(who.account().unwrap_or("000000000000").to_string())
    }

    fn arn_instance(region: &str, account: &str, instance_id: &str) -> String {
        format!("arn:aws:ec2:{region}:{account}:instance/{instance_id}")
    }

    fn arn_volume(region: &str, account: &str, volume_id: &str) -> String {
        format!("arn:aws:ec2:{region}:{account}:volume/{volume_id}")
    }
}

#[async_trait]
impl Collector for EC2Collector {
    fn name(&self) -> &'static str {
        "ec2"
    }

    async fn discover(&self, regions: &[String], mock: bool) -> anyhow::Result<Vec<Asset>> {
        // --- MOCK ---
        if mock {
            let mut meta = JsonMap::new();
            meta.insert("state".into(), json!("running"));
            meta.insert("instance_type".into(), json!("t3.medium"));

            let mut out = vec![];

            out.push(Asset {
                id: "arn:aws:ec2:ap-northeast-2:111122223333:instance/i-0123456789abcdef0".into(),
                service: "ec2".into(),
                kind: AssetKind::Compute,
                region: "ap-northeast-2".into(),
                name: Some("i-0123456789abcdef0".into()),
                uri: Some("ec2://i-0123456789abcdef0".into()),
                size_bytes: None,
                encrypted: None,
                kms_key_id: None,
                tags: HashMap::from([("env".into(), "dev".into())]),
                metadata: Self::jsonmap_into_hashmap(meta),
            });

            let mut vol_meta = JsonMap::new();
            vol_meta.insert("encrypted".into(), json!(true));
            out.push(Asset {
                id: "arn:aws:ec2:ap-northeast-2:111122223333:volume/vol-0abcde12345f67890".into(),
                service: "ec2".into(),
                kind: AssetKind::BlockStorage,
                region: "ap-northeast-2".into(),
                name: Some("vol-0abcde12345f67890".into()),
                uri: Some("ec2://volume/vol-0abcde12345f67890".into()),
                size_bytes: Some(100 * 1024 * 1024 * 1024),
                encrypted: Some(true),
                kms_key_id: Some("arn:aws:kms:ap-northeast-2:111122223333:key/mock-kms".into()),
                tags: HashMap::from([("env".into(), "dev".into())]),
                metadata: Self::jsonmap_into_hashmap(vol_meta),
            });

            return Ok(out);
        }

        // --- REAL ---
        let account_id = Self::get_account_id().await.unwrap_or_else(|_| "000000000000".into());
        let mut out_assets: Vec<Asset> = Vec::new();

        for region in regions {
            // deprecated 대체: defaults(BehaviorVersion::latest())
            let conf = aws_config::defaults(BehaviorVersion::latest())
                .region(Region::new(region.clone()))
                .load()
                .await;

            let ec2_client = ec2::Client::new(&conf);

            // 1) Instances
            let mut token: Option<String> = None;
            loop {
                let mut req = ec2_client.describe_instances();
                if let Some(t) = token.as_deref() {
                    req = req.next_token(t);
                }
                let resp = req.send().await?;

                for res in resp.reservations() {
                    for inst in res.instances() {
                        let instance_id = match inst.instance_id() {
                            Some(v) => v.to_string(),
                            None => continue,
                        };

                        let tags = Self::tags_to_hashmap(inst.tags());

                        let mut meta = JsonMap::new();
                        if let Some(st) = inst.state().and_then(|s| s.name()) {
                            meta.insert("state".into(), json!(st.as_ref()));
                        }
                        if let Some(it) = inst.instance_type() {
                            meta.insert("instance_type".into(), json!(it.as_str()));
                        }
                        if let Some(plat) = inst.platform_details() {
                            meta.insert("platform".into(), json!(plat));
                        }
                        if let Some(priv_ip) = inst.private_ip_address() {
                            meta.insert("private_ip".into(), json!(priv_ip));
                        }
                        if let Some(pub_ip) = inst.public_ip_address() {
                            meta.insert("public_ip".into(), json!(pub_ip));
                        }
                        if let Some(vpc) = inst.vpc_id() {
                            meta.insert("vpc_id".into(), json!(vpc));
                        }
                        if let Some(subnet) = inst.subnet_id() {
                            meta.insert("subnet_id".into(), json!(subnet));
                        }
                        if let Some(lt) = inst.launch_time() {
                            meta.insert("launch_time".into(), json!(lt.to_string()));
                        }
                        if let Some(iam) = inst.iam_instance_profile().and_then(|p| p.arn()) {
                            meta.insert("iam_instance_profile_arn".into(), json!(iam));
                        }
                        if let Some(ebs_opt) = inst.ebs_optimized() {
                            meta.insert("ebs_optimized".into(), json!(ebs_opt));
                        }

                        let arn = Self::arn_instance(region, &account_id, &instance_id);
                        let asset = Asset {
                            id: arn,
                            service: "ec2".into(),
                            kind: AssetKind::Compute,
                            region: region.clone(),
                            name: Some(instance_id.clone()),
                            uri: Some(format!("ec2://{}", instance_id)),
                            size_bytes: None,
                            encrypted: None,
                            kms_key_id: None,
                            tags,
                            metadata: Self::jsonmap_into_hashmap(meta),
                        };
                        out_assets.push(asset);
                    }
                }

                token = resp.next_token().map(|s| s.to_string());
                if token.is_none() {
                    break;
                }
            }

            // 2) Volumes
            let mut vtoken: Option<String> = None;
            loop {
                let mut req = ec2_client.describe_volumes();
                if let Some(t) = vtoken.as_deref() {
                    req = req.next_token(t);
                }
                let resp = req.send().await?;

                for vol in resp.volumes() {
                    let vol_id = match vol.volume_id() {
                        Some(v) => v.to_string(),
                        None => continue,
                    };

                    let tags = Self::tags_to_hashmap(vol.tags());

                    let mut meta = JsonMap::new();
                    if let Some(st) = vol.state() {
                        meta.insert("state".into(), json!(st.as_str()));
                    }
                    if let Some(iops) = vol.iops() {
                        meta.insert("iops".into(), json!(iops));
                    }
                    if let Some(throughput) = vol.throughput() {
                        meta.insert("throughput".into(), json!(throughput));
                    }
                    if let Some(voltype) = vol.volume_type() {
                        meta.insert("volume_type".into(), json!(voltype.as_str()));
                    }

                    let atts: Vec<Value> = vol
                        .attachments()
                        .iter()
                        .map(|a| {
                            json!({
                                "instance_id": a.instance_id(),
                                "state": a.state().map(|s| s.as_str()),
                                "device": a.device()
                            })
                        })
                        .collect();
                    meta.insert("attachments".into(), Value::Array(atts));

                    let size_bytes = vol.size().map(|sz_gib| (sz_gib as u64) * 1024 * 1024 * 1024);
                    let encrypted = vol.encrypted();
                    let kms_key = vol.kms_key_id().map(|s| s.to_string());

                    let arn = Self::arn_volume(region, &account_id, &vol_id);
                    let asset = Asset {
                        id: arn,
                        service: "ec2".into(),
                        kind: AssetKind::BlockStorage,
                        region: region.clone(),
                        name: Some(vol_id.clone()),
                        uri: Some(format!("ec2://volume/{}", vol_id)),
                        size_bytes,
                        encrypted,
                        kms_key_id: kms_key,
                        tags,
                        metadata: Self::jsonmap_into_hashmap(meta),
                    };
                    out_assets.push(asset);
                }

                vtoken = resp.next_token().map(|s| s.to_string());
                if vtoken.is_none() {
                    break;
                }
            }
        }

        Ok(out_assets)
    }
}
