use crate::collector_core::Asset;
use anyhow::Result;

pub mod http;

#[derive(Clone, Copy, Debug)]
pub enum OutMode {
    Stdout,
    Http,
}

impl OutMode {
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "http" => OutMode::Http,
            _ => OutMode::Stdout,
        }
    }
}

pub async fn emit_stdout(assets: &[Asset]) -> Result<()> {
    println!("discovered assets = {}", assets.len());
    println!("{}", serde_json::to_string_pretty(&assets)?);
    Ok(())
}
