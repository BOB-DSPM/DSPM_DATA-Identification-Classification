use crate::collector_core::*; use async_trait::async_trait; use aws_types::region::Region;

pub struct SqsCollector;
#[async_trait]
impl Collector for SqsCollector {
    fn name(&self) -> &'static str { "sqs" }
    async fn discover(&self, regions: &[String]) -> anyhow::Result<Vec<Asset>> {
        use aws_sdk_sqs as sqs;
        let mut out = vec![];
        for r in regions {
            let conf = aws_config::from_env().region(Region::new(r.clone())).load().await;
            let c = sqs::Client::new(&conf);
            let qs = c.list_queues().send().await?;
            for url in qs.queue_urls().unwrap_or_default() {
                out.push(Asset{
                    id: url.to_string(), service: "sqs".into(), kind: AssetKind::Queue,
                    region: r.clone(), name: Some(url.split('/').last().unwrap_or("").to_string()),
                    uri: Some(url.to_string()), size_bytes: None,
                    encrypted: None, kms_key_id: None, tags: Default::default(), metadata: Default::default(),
                });
            }
        }
        Ok(out)
    }
}

pub struct SnsCollector; // list_topics → Topic
pub struct EventBridgeCollector; // list_event_buses / list_rules → EventBus
pub struct MqCollector; // list_brokers → broker ARN (ActiveMQ/RabbitMQ)