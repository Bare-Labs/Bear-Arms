use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::types::{Finding, Severity};

#[derive(Debug, Clone)]
pub struct RuleSet {
    pub known_bad_hashes: std::collections::HashSet<String>,
    pub suspicious_names: std::collections::HashSet<String>,
    pub suspicious_extensions: std::collections::HashSet<String>,
    pub max_file_mb: u64,
}

impl RuleSet {
    pub fn evaluate(&self, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            let lowered = name.to_ascii_lowercase();
            if self.suspicious_names.contains(&lowered) {
                findings.push(Finding {
                    path: path.to_path_buf(),
                    rule_id: "name.suspicious".to_string(),
                    reason: format!("filename matches suspicious indicator: {name}"),
                    severity: Severity::Medium,
                    score: 30,
                    sha256: None,
                });
            }
        }

        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            let normalized = format!(".{}", ext.to_ascii_lowercase());
            if self.suspicious_extensions.contains(&normalized) {
                findings.push(Finding {
                    path: path.to_path_buf(),
                    rule_id: "ext.suspicious".to_string(),
                    reason: format!("suspicious extension detected: {normalized}"),
                    severity: Severity::Medium,
                    score: 25,
                    sha256: None,
                });
            }
        }

        if let Ok(meta) = std::fs::metadata(path) {
            let size_mb = meta.len() / (1024 * 1024);
            if size_mb > self.max_file_mb {
                findings.push(Finding {
                    path: path.to_path_buf(),
                    rule_id: "size.anomalous".to_string(),
                    reason: format!("file exceeds size threshold ({size_mb} MB)"),
                    severity: Severity::Low,
                    score: 10,
                    sha256: None,
                });
            }
        }

        if let Ok(digest) = sha256(path) {
            if self.known_bad_hashes.contains(&digest) {
                findings.push(Finding {
                    path: path.to_path_buf(),
                    rule_id: "hash.known_bad".to_string(),
                    reason: "sha256 matched known-bad indicator".to_string(),
                    severity: Severity::High,
                    score: 90,
                    sha256: Some(digest),
                });
            }
        }

        findings
    }
}

pub fn sha256(path: &Path) -> anyhow::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buf = [0_u8; 64 * 1024];

    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        digest.update(&buf[..n]);
    }

    Ok(format!("{:x}", digest.finalize()))
}
