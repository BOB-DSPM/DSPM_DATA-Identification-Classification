// src/ecr.rs
use anyhow::Result;
use aws_sdk_ecr as ecr;
use aws_types::region::Region;
use aws_config::BehaviorVersion;
use serde_json::json;
use crate::types::Asset;

pub async fn discover_ecr(_cfg: &aws_config::SdkConfig, region: &str) -> Result<Vec<Asset>> {
    // 지역별 클라이언트
    let regional_cfg = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new(region.to_string()))
        .load()
        .await;
    let client = ecr::Client::new(&regional_cfg);

    let mut out = Vec::<Asset>::new();
    let mut repo_token: Option<String> = None;

    loop {
        let mut rreq = client.describe_repositories();
        if let Some(t) = &repo_token {
            rreq = rreq.next_token(t);
        }
        let rresp = rreq.send().await?;

        for repo in rresp.repositories().iter() {
            let repo_name = repo.repository_name().unwrap_or_default();

            let mut img_token: Option<String> = None;
            loop {
                let mut ireq = client.describe_images().repository_name(repo_name);
                if let Some(t) = &img_token {
                    ireq = ireq.next_token(t);
                }
                let iresp = ireq.send().await?;

                for d in iresp.image_details().iter() {
                    // tags: &[String] → Vec<String>
                    let tags: Vec<String> = d.image_tags().to_vec();
                    let first_tag = tags.first().cloned().unwrap_or_default();

                    let locator = if first_tag.is_empty() {
                        format!("ecr://{}@{}", repo_name, d.image_digest().unwrap_or_default())
                    } else {
                        format!("ecr://{}:{}", repo_name, first_tag)
                    };

                    let meta = json!({
                        "service": "ecr",
                        "tags": tags,
                        "digest": d.image_digest(),
                        "size_bytes": d.image_size_in_bytes(),
                        "pushed_at": d.image_pushed_at().map(|t| t.to_string())
                    });

                    out.push(Asset {
                        kind: "image".into(),
                        locator,
                        name: if first_tag.is_empty() {
                            repo_name.to_string()
                        } else {
                            format!("{}:{}", repo_name, first_tag)
                        },
                        region: region.to_string(),
                        bytes: d.image_size_in_bytes().map(|v| v as i64),
                        meta,
                    });
                }

                img_token = iresp.next_token().map(|s| s.to_string());
                if img_token.is_none() {
                    break;
                }
            }
        }

        repo_token = rresp.next_token().map(|s| s.to_string());
        if repo_token.is_none() {
            break;
        }
    }

    Ok(out)
}
