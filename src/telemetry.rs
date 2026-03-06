use std::path::Path;

use anyhow::Context;
use chrono::Utc;
use serde::Serialize;

use crate::types::Finding;

#[derive(Debug, Serialize)]
struct AuditEvent<'a> {
    timestamp: String,
    action: &'a str,
    rule_id: &'a str,
    severity: &'a str,
    reason: &'a str,
    path: String,
    score: u32,
    sha256: Option<&'a str>,
}

pub fn write_audit_event(path: &Path, finding: &Finding, action: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create audit log parent {}", parent.display()))?;
    }

    let severity = match finding.severity {
        crate::types::Severity::Low => "low",
        crate::types::Severity::Medium => "medium",
        crate::types::Severity::High => "high",
    };

    let event = AuditEvent {
        timestamp: Utc::now().to_rfc3339(),
        action,
        rule_id: &finding.rule_id,
        severity,
        reason: &finding.reason,
        path: finding.path.display().to_string(),
        score: finding.score,
        sha256: finding.sha256.as_deref(),
    };

    let mut line = serde_json::to_string(&event).context("failed to serialize audit event")?;
    line.push('\n');

    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open audit log at {}", path.display()))?;
    file.write_all(line.as_bytes())
        .with_context(|| format!("failed to write audit log line to {}", path.display()))?;

    Ok(())
}
