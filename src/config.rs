use std::path::PathBuf;

use anyhow::Context;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Heuristics {
    #[serde(default = "default_max_file_mb")]
    pub max_file_mb: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Indicators {
    #[serde(default)]
    pub known_bad_hashes: Vec<String>,
    #[serde(default)]
    pub suspicious_names: Vec<String>,
    #[serde(default)]
    pub suspicious_extensions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScannerConfig {
    pub watch_paths: Vec<PathBuf>,
    #[serde(default)]
    pub exclude_globs: Vec<String>,
    pub quarantine_dir: PathBuf,
    pub audit_log_path: PathBuf,
    pub heuristics: Heuristics,
    pub indicators: Indicators,
}

fn default_max_file_mb() -> u64 {
    200
}

pub fn load_config(path: &PathBuf) -> anyhow::Result<ScannerConfig> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config at {}", path.display()))?;
    let cfg: ScannerConfig = serde_yaml::from_str(&raw)
        .with_context(|| format!("failed to parse YAML config at {}", path.display()))?;
    Ok(cfg)
}
