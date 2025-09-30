use anyhow::Result;

pub fn chunked<T: Clone>(v: &[T], size: usize) -> Vec<Vec<T>> {
    v.chunks(size).map(|c| c.to_vec()).collect()
}

// 임시: EC2 SDK 없이 고정 리전만 사용
pub async fn list_enabled_regions(_cfg: &aws_config::SdkConfig) -> Result<Vec<String>> {
    Ok(vec!["ap-northeast-2".to_string()]) // 서울만
}
// pub async fn list_enabled_regions(cfg: &aws_config::SdkConfig) -> Result<Vec<String>> {
//    use aws_sdk_ec2 as ec2;
//    let client = ec2::Client::new(cfg);
//    let resp = client.describe_regions().all_regions(false).send().await?;
//    let regions = resp
//        .regions()
//        .iter()
//        .filter_map(|r| r.region_name().map(|s| s.to_string()))
//        .collect::<Vec<_>>();
//   Ok(regions)
//}

pub fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}
