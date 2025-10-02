use crate::collector_core::*;
use anyhow::Result;
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_dynamodb as ddb;
use serde_json::json;
use std::collections::HashMap;

pub struct DynamodbCollector;
impl DynamodbCollector { pub fn new() -> Self { Self } }

#[async_trait]
impl Collector for DynamodbCollector {
  fn name(&self) -> &'static str { "dynamodb" }

  async fn discover(&self, regions: &[String], _mock: bool) -> Result<Vec<Asset>> {
    let base = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let mut out = Vec::new();

    for region in regions {
      let conf = aws_config::from_env()
        .region(aws_types::region::Region::new(region.clone()))
        .load().await;
      let client = ddb::Client::new(&conf);

      // 테이블 이름 페이지네이션
      let mut last_evaluated: Option<String> = None;
      let mut all_names: Vec<String> = Vec::new();
      loop {
        let mut b = client.list_tables();
        if let Some(tok) = &last_evaluated { b = b.exclusive_start_table_name(tok); }
        // limit은 paginator 쓰지 않을 땐 여기서 지정
        b = b.limit(100);
        let resp = b.send().await?;
        for n in resp.table_names() { all_names.push(n.to_string()); }
        last_evaluated = resp.last_evaluated_table_name().map(|s| s.to_string());
        if last_evaluated.is_none() { break; }
      }

      for name in all_names {
        let desc = client.describe_table().table_name(&name).send().await?;
        let table = match desc.table() { Some(t) => t, None => continue };

        // 보관 모드 등 메타데이터
        let mut md: HashMap<String, serde_json::Value> = HashMap::new();
        if let Some(bm) = table.billing_mode_summary() {
          if let Some(m) = bm.billing_mode() { md.insert("billing_mode".into(), json!(m.as_str())); }
        }
        if let Some(pitr) = table.continuous_backups_description() {
          if let Some(status) = pitr.point_in_time_recovery_description()
                                    .and_then(|d| d.point_in_time_recovery_status()) {
            md.insert("pitr_status".into(), json!(status.as_str()));
          }
        }
        if let Some(sse) = table.sse_description() {
          if let Some(st) = sse.status() { md.insert("sse_status".into(), json!(st.as_str())); }
          if let Some(k) = sse.kms_master_key_arn() { md.insert("kms_key_arn".into(), json!(k)); }
          if let Some(typ) = sse.sse_type() { md.insert("sse_type".into(), json!(typ.as_str())); }
        }

        // 태그 (리소스 ARN 필요)
        let mut tags_map: HashMap<String, String> = HashMap::new();
        if let Some(arn) = table.table_arn() {
          if let Ok(tagres) = client.list_tags_of_resource().resource_arn(arn).send().await {
            for t in tagres.tags() {               // &[Tag]
              if let (Some(k), Some(v)) = (t.key(), t.value()) {
                tags_map.insert(k.to_string(), v.to_string());
              }
            }
          }
        }

        out.push(Asset{
          id: table.table_arn().unwrap_or(&name).to_string(),
          service: "dynamodb".into(),
          kind: AssetKind::ObjectStore,
          region: region.clone(),
          name: Some(name.clone()),
          uri: Some(format!("dynamodb://{}/{}", region, name)),
          size_bytes: None,
          encrypted: table.sse_description().and_then(|s| s.status()).map(|st| st.as_str() == "ENABLED"),
          kms_key_id: table.sse_description().and_then(|s| s.kms_master_key_arn()).map(|s| s.to_string()),
          tags: tags_map,
          metadata: md
        });
      }
    }

    Ok(out)
  }
}
