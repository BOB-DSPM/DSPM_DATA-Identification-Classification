mod s3;

use crate::collector_core::Collector;
use anyhow::Result;
use std::sync::Arc;

pub enum ServiceKind {
    S3,
}

impl ServiceKind {
    pub fn parse_list(s: &str) -> Vec<ServiceKind> {
        s.split(',')
            .filter_map(|x| match x.trim().to_lowercase().as_str() {
                "s3" => Some(ServiceKind::S3),
                _ => None,
            })
            .collect()
    }
}

pub fn build_collectors(services: &[ServiceKind]) -> Result<Vec<Arc<dyn Collector>>> {
    let mut v: Vec<Arc<dyn Collector>> = vec![];
    for svc in services {
        match svc {
            ServiceKind::S3 => v.push(Arc::new(s3::S3Collector::new())),
        }
    }
    Ok(v)
}
