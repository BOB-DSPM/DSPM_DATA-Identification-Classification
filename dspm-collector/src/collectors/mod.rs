pub mod s3;                 
pub mod ec2;               
pub mod cloudwatch_logs;   
pub mod ebs;               
pub mod ecr;      
pub mod cloudtrail;          
pub mod sqs;
pub mod opensearch; 
pub mod backup;
pub mod sns;
pub mod kinesis;

use crate::collector_core::Collector;
use std::sync::Arc;

#[derive(Debug, Clone, Copy)]
pub enum ServiceKind {
    S3,
    EC2,            
    CloudWatchLogs, 
    EC2Ebs,        
    Ecr,           
    CloudTrail,
    SQS, 
    OpenSearch,
    Backup,
    SNS,
    Kinesis,
}

impl ServiceKind {
    pub fn parse_list(s: &str) -> Vec<ServiceKind> {
        s.split(',')
            .filter_map(|x| match x.trim().to_lowercase().as_str() {
                "s3" => Some(ServiceKind::S3),
                "ec2" => Some(ServiceKind::EC2), // (있다면 유지)
                "cloudwatch-logs" | "logs" => Some(ServiceKind::CloudWatchLogs),
                "ec2-ebs" | "ebs" => Some(ServiceKind::EC2Ebs),
                "ecr" => Some(ServiceKind::Ecr),
                "cloudtrail" => Some(ServiceKind::CloudTrail),
                "sqs" => Some(ServiceKind::SQS),
                "opensearch" | "es" => Some(ServiceKind::OpenSearch),
                "backup" => Some(ServiceKind::Backup),
                "sns" => Some(ServiceKind::SNS),
                "kinesis" => Some(ServiceKind::Kinesis),
                _ => None,
            })
            .collect()
    }
}

pub fn build_collectors(services: &[ServiceKind]) -> anyhow::Result<Vec<Arc<dyn Collector>>> {
    let mut v: Vec<Arc<dyn Collector>> = vec![];
    for svc in services {
        match svc {
            ServiceKind::S3 => v.push(Arc::new(s3::S3Collector::new())),
            ServiceKind::EC2 => v.push(Arc::new(crate::collectors::ec2::EC2Collector::new())),
            ServiceKind::CloudWatchLogs => v.push(Arc::new(cloudwatch_logs::CloudWatchLogsCollector::new())),
            ServiceKind::EC2Ebs => v.push(Arc::new(ebs::EbsCollector::new())),
            ServiceKind::Ecr => v.push(Arc::new(ecr::EcrCollector::new())),
            ServiceKind::CloudTrail => v.push(Arc::new(cloudtrail::CloudTrailCollector::new())),
            ServiceKind::SQS => v.push(Arc::new(sqs::SqsCollector::new())),
            ServiceKind::OpenSearch => v.push(Arc::new(opensearch::OpenSearchCollector::new())),
            ServiceKind::Backup => v.push(Arc::new(backup::BackupCollector::new())),
            ServiceKind::SNS => v.push(Arc::new(sns::SnsCollector::new())),
            ServiceKind::Kinesis => v.push(Arc::new(kinesis::KinesisCollector::new())),
        }
    }
    Ok(v)
}
