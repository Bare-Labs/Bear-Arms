use std::path::PathBuf;

use rmcp::handler::server::{tool::ToolRouter, wrapper::Parameters};
use rmcp::model::*;
use rmcp::schemars;
use rmcp::{tool, tool_handler, tool_router, ErrorData, ServerHandler};
use serde::Deserialize;

use crate::config::load_config;
use crate::types::Severity;
use crate::{analysis, harden, quarantine, scanner, triage};

// ── Server struct ─────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct BearArmsServer {
    config_path: PathBuf,
    tool_router: ToolRouter<Self>,
}

impl BearArmsServer {
    pub fn new(config_path: PathBuf) -> Self {
        Self {
            config_path,
            tool_router: Self::tool_router(),
        }
    }
}

// ── Tool parameter types ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ScanParams {
    /// Absolute path to scan. If omitted, uses watch_paths from config.
    pub path: Option<String>,
    /// If true, High-severity findings are moved to the quarantine directory.
    #[serde(default)]
    pub quarantine: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AnalyzeParams {
    /// Absolute path to the auth log.
    /// Defaults to /var/log/auth.log (Debian/Ubuntu) or /var/log/secure (RHEL).
    pub log_path: Option<String>,
}

// ── Helper ────────────────────────────────────────────────────────────────────

fn json_result(value: &impl serde::Serialize) -> CallToolResult {
    match serde_json::to_string_pretty(value) {
        Ok(json) => CallToolResult::success(vec![Content::text(json)]),
        Err(e) => {
            CallToolResult::error(vec![Content::text(format!("serialization error: {e}"))])
        }
    }
}

// ── Tool implementations ──────────────────────────────────────────────────────

#[tool_router]
impl BearArmsServer {
    /// Scan files for malware indicators: known-bad SHA256 hashes, suspicious
    /// filenames, suspicious extensions, and file size anomalies.
    #[tool(description = "Scan files for malware indicators: known-bad SHA256 hashes, suspicious filenames, suspicious extensions, and file size anomalies. Returns a JSON array of findings.")]
    async fn scan(
        &self,
        Parameters(params): Parameters<ScanParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let cfg = match load_config(&self.config_path) {
            Ok(c) => c,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "config error: {e}"
                ))]));
            }
        };

        let target_paths = if let Some(ref p) = params.path {
            vec![PathBuf::from(p)]
        } else {
            cfg.watch_paths.clone()
        };

        let findings = match scanner::scan_paths(&target_paths, &cfg) {
            Ok(f) => f,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "scan error: {e}"
                ))]));
            }
        };

        if params.quarantine {
            for finding in &findings {
                if finding.severity == Severity::High && finding.path.exists() {
                    let _ = quarantine::quarantine_file(&finding.path, &cfg.quarantine_dir);
                }
            }
        }

        Ok(json_result(&findings))
    }

    /// Snapshot the live system: running processes, open TCP/TCP6 connections,
    /// and active persistence mechanisms (cron jobs, systemd units, shell RC files).
    #[tool(description = "Snapshot running processes, open network connections, and persistence mechanisms (cron, systemd units, shell RC files). Returns a JSON TriageReport.")]
    async fn triage(&self) -> Result<CallToolResult, ErrorData> {
        match triage::collect() {
            Ok(report) => Ok(json_result(&report)),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "triage error: {e}"
            ))])),
        }
    }

    /// Parse authentication logs for suspicious patterns: SSH brute-force,
    /// successful logins, sudo usage, and account creation.
    #[tool(description = "Parse authentication logs for suspicious patterns: SSH brute-force attempts, successful logins, sudo usage, and account creation events. Returns a JSON array of anomalies.")]
    async fn analyze(
        &self,
        Parameters(params): Parameters<AnalyzeParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let log_path = params
            .log_path
            .map(PathBuf::from)
            .unwrap_or_else(analysis::default_log_path);

        let anomalies = analysis::run(&log_path);
        Ok(json_result(&anomalies))
    }

    /// Audit system hardening posture: SSH config, SUID/SGID binaries,
    /// world-writable files, password shadowing, and umask.
    #[tool(description = "Audit system hardening posture: SSH configuration, SUID/SGID binaries, world-writable files, password shadowing, and umask. Returns a JSON array of findings with severity and remediation steps.")]
    async fn harden(&self) -> Result<CallToolResult, ErrorData> {
        let findings = harden::run();
        Ok(json_result(&findings))
    }
}

// ── ServerHandler ─────────────────────────────────────────────────────────────

#[tool_handler]
impl ServerHandler for BearArmsServer {
    fn get_info(&self) -> ServerInfo {
        // ServerInfo (= InitializeResult) is #[non_exhaustive]; modify via Default
        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.instructions = Some(
            "Blue team cybersecurity toolkit for macOS/Linux homelabs. \
             Tools: scan (malware detection), triage (process/network/persistence snapshot), \
             analyze (auth log anomaly detection), harden (system hardening assessment)."
                .into(),
        );
        info
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn serve(config_path: PathBuf) -> anyhow::Result<()> {
    use rmcp::transport::stdio;
    use rmcp::ServiceExt;

    let server = BearArmsServer::new(config_path);
    let service = server
        .serve(stdio())
        .await
        .map_err(|e| anyhow::anyhow!("MCP serve error: {e}"))?;

    service
        .waiting()
        .await
        .map_err(|e| anyhow::anyhow!("MCP server exited with error: {e}"))?;

    Ok(())
}
