use std::path::PathBuf;

use serde::{Deserialize, Serialize};

// ── Existing scanner types ────────────────────────────────────────────────────

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

// ── Triage types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub name: String,
    pub exe: Option<String>,
    pub cmdline: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetConnection {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceEntry {
    pub kind: String,
    pub source: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageReport {
    pub timestamp: String,
    pub hostname: String,
    pub processes: Vec<ProcessInfo>,
    pub connections: Vec<NetConnection>,
    pub persistence: Vec<PersistenceEntry>,
}

// ── Log analysis types ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogAnomaly {
    pub event_type: String,
    pub description: String,
    pub count: usize,
    pub examples: Vec<String>,
}

// ── Hardening types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HardenSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardenFinding {
    pub check_id: String,
    pub severity: HardenSeverity,
    pub description: String,
    pub detail: String,
    pub remediation: String,
}
