mod analysis;
mod config;
mod harden;
mod quarantine;
mod rules;
mod scanner;
mod telemetry;
mod triage;
mod types;

use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};

use crate::config::load_config;
use crate::types::{HardenSeverity, Severity};

#[derive(Debug, Parser)]
#[command(name = "bear-arms")]
#[command(about = "Blue team cybersecurity toolkit for macOS and Linux homelabs")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Validate config and check that watch paths exist.
    Doctor {
        #[arg(long, default_value = "config/default.yaml")]
        config: PathBuf,
    },

    /// Scan files for known-bad hashes, suspicious names, and anomalies.
    Scan {
        #[arg(long, default_value = "config/default.yaml")]
        config: PathBuf,
        #[arg(long)]
        path: Option<PathBuf>,
        #[arg(long)]
        quarantine: bool,
    },

    /// Snapshot running processes, open network connections, and persistence mechanisms.
    Triage {
        /// Write the full report as JSON to this file.
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Parse authentication logs for suspicious patterns (brute force, privilege escalation, etc.).
    Analyze {
        /// Path to auth log. Defaults to /var/log/auth.log or /var/log/secure.
        #[arg(long)]
        log: Option<PathBuf>,
    },

    /// Check system hardening posture (SSH config, SUID binaries, world-writable files, etc.).
    Harden {
        /// Exit with non-zero status if any Critical findings are found.
        #[arg(long)]
        strict: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Doctor { config } => cmd_doctor(config),
        Commands::Scan {
            config,
            path,
            quarantine,
        } => cmd_scan(config, path, quarantine),
        Commands::Triage { output } => cmd_triage(output),
        Commands::Analyze { log } => cmd_analyze(log),
        Commands::Harden { strict } => cmd_harden(strict),
    }
}

// ── doctor ────────────────────────────────────────────────────────────────────

fn cmd_doctor(config_path: PathBuf) -> anyhow::Result<()> {
    let cfg = load_config(&config_path)?;

    println!("Config: {}", config_path.display());
    println!("Watch paths: {}", cfg.watch_paths.len());
    println!("Quarantine: {}", cfg.quarantine_dir.display());
    println!("Audit log: {}", cfg.audit_log_path.display());

    let missing: Vec<String> = cfg
        .watch_paths
        .iter()
        .filter(|p| !p.exists())
        .map(|p| p.display().to_string())
        .collect();

    if !missing.is_empty() {
        for path in missing {
            println!("Missing path: {path}");
        }
        anyhow::bail!("one or more watch paths do not exist");
    }

    println!("Doctor checks passed.");
    Ok(())
}

// ── scan ──────────────────────────────────────────────────────────────────────

fn cmd_scan(
    config_path: PathBuf,
    manual_path: Option<PathBuf>,
    do_quarantine: bool,
) -> anyhow::Result<()> {
    let cfg = load_config(&config_path)?;

    let target_paths = if let Some(path) = manual_path {
        vec![path]
    } else {
        cfg.watch_paths.clone()
    };

    let findings = scanner::scan_paths(&target_paths, &cfg)?;

    if findings.is_empty() {
        println!("No findings.");
        return Ok(());
    }

    let mut aggregate_score: u32 = 0;

    for finding in findings {
        aggregate_score += finding.score;
        println!(
            "[{:?}] {} | {} | {}",
            finding.severity,
            finding.rule_id,
            finding.path.display(),
            finding.reason
        );

        let mut action = "alert";
        if do_quarantine && finding.severity == Severity::High && finding.path.exists() {
            let moved = quarantine::quarantine_file(&finding.path, &cfg.quarantine_dir)
                .with_context(|| "failed during quarantine move")?;
            action = "quarantine";
            println!("  -> moved to {}", moved.display());
        }

        telemetry::write_audit_event(&cfg.audit_log_path, &finding, action)?;
    }

    println!("Scan complete: aggregate score={aggregate_score}");
    Ok(())
}

// ── triage ────────────────────────────────────────────────────────────────────

fn cmd_triage(output: Option<PathBuf>) -> anyhow::Result<()> {
    println!("Collecting triage snapshot...");
    let report = triage::collect()?;

    println!("Hostname   : {}", report.hostname);
    println!("Timestamp  : {}", report.timestamp);
    println!("Processes  : {}", report.processes.len());
    println!("Connections: {}", report.connections.len());

    // Count listen vs established
    let listening = report
        .connections
        .iter()
        .filter(|c| c.state == "LISTEN")
        .count();
    let established = report
        .connections
        .iter()
        .filter(|c| c.state == "ESTABLISHED")
        .count();
    println!("  LISTEN={listening}  ESTABLISHED={established}");

    println!("Persistence: {} entries found", report.persistence.len());
    for entry in &report.persistence {
        println!("  [{}] {} -> {}", entry.kind, entry.source, entry.detail);
    }

    if let Some(out_path) = output {
        let json = serde_json::to_string_pretty(&report)?;
        std::fs::write(&out_path, json)
            .with_context(|| format!("failed to write triage report to {}", out_path.display()))?;
        println!("Report written to {}", out_path.display());
    }

    Ok(())
}

// ── analyze ───────────────────────────────────────────────────────────────────

fn cmd_analyze(log: Option<PathBuf>) -> anyhow::Result<()> {
    let log_path = log.unwrap_or_else(analysis::default_log_path);

    println!("Analyzing: {}", log_path.display());

    let anomalies = analysis::run(&log_path);

    if anomalies.is_empty() {
        println!("No anomalies detected.");
        return Ok(());
    }

    for anomaly in &anomalies {
        println!("\n[{}] {}", anomaly.event_type, anomaly.description);
        for example in &anomaly.examples {
            println!("  {example}");
        }
    }

    println!("\nTotal event categories: {}", anomalies.len());
    Ok(())
}

// ── harden ────────────────────────────────────────────────────────────────────

fn cmd_harden(strict: bool) -> anyhow::Result<()> {
    println!("Running hardening checks...\n");
    let findings = harden::run();

    if findings.is_empty() {
        println!("No hardening issues found.");
        return Ok(());
    }

    let mut has_critical = false;

    for f in &findings {
        let label = match f.severity {
            HardenSeverity::Critical => {
                has_critical = true;
                "CRIT "
            }
            HardenSeverity::Warning => "WARN ",
            HardenSeverity::Info => "INFO ",
        };
        println!("[{label}] [{}] {}", f.check_id, f.description);
        println!("       Detail     : {}", f.detail);
        println!("       Remediation: {}", f.remediation);
        println!();
    }

    let criticals = findings
        .iter()
        .filter(|f| matches!(f.severity, HardenSeverity::Critical))
        .count();
    let warnings = findings
        .iter()
        .filter(|f| matches!(f.severity, HardenSeverity::Warning))
        .count();
    let infos = findings
        .iter()
        .filter(|f| matches!(f.severity, HardenSeverity::Info))
        .count();

    println!(
        "Summary: {} critical, {} warnings, {} informational",
        criticals, warnings, infos
    );

    if strict && has_critical {
        anyhow::bail!("--strict: critical hardening issues found");
    }

    Ok(())
}
