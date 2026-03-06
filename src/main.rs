mod config;
mod quarantine;
mod rules;
mod scanner;
mod telemetry;
mod types;

use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};

use crate::config::load_config;
use crate::types::Severity;

#[derive(Debug, Parser)]
#[command(name = "bear-arms")]
#[command(about = "Homelab antivirus/antimalware scanner for macOS/Linux")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Doctor {
        #[arg(long, default_value = "config/default.yaml")]
        config: PathBuf,
    },
    Scan {
        #[arg(long, default_value = "config/default.yaml")]
        config: PathBuf,
        #[arg(long)]
        path: Option<PathBuf>,
        #[arg(long)]
        quarantine: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Doctor { config } => doctor(config),
        Commands::Scan {
            config,
            path,
            quarantine,
        } => scan(config, path, quarantine),
    }
}

fn doctor(config_path: PathBuf) -> anyhow::Result<()> {
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

fn scan(config_path: PathBuf, manual_path: Option<PathBuf>, do_quarantine: bool) -> anyhow::Result<()> {
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
