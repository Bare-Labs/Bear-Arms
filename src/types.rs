use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub path: PathBuf,
    pub rule_id: String,
    pub reason: String,
    pub severity: Severity,
    pub score: u32,
    pub sha256: Option<String>,
}
