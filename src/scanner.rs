use std::path::PathBuf;

use anyhow::Context;
use globset::GlobSetBuilder;
use walkdir::WalkDir;

use crate::config::ScannerConfig;
use crate::rules::RuleSet;
use crate::types::Finding;

pub fn scan_paths(paths: &[PathBuf], cfg: &ScannerConfig) -> anyhow::Result<Vec<Finding>> {
    let mut builder = GlobSetBuilder::new();
    for pattern in &cfg.exclude_globs {
        builder.add(globset::Glob::new(pattern).with_context(|| {
            format!("invalid exclude glob pattern in config: {pattern}")
        })?);
    }
    let glob_set = builder.build().context("failed to compile exclude globs")?;

    let rules = RuleSet {
        known_bad_hashes: cfg
            .indicators
            .known_bad_hashes
            .iter()
            .map(|h| h.to_ascii_lowercase())
            .collect(),
        suspicious_names: cfg
            .indicators
            .suspicious_names
            .iter()
            .map(|n| n.to_ascii_lowercase())
            .collect(),
        suspicious_extensions: cfg
            .indicators
            .suspicious_extensions
            .iter()
            .map(|e| e.to_ascii_lowercase())
            .collect(),
        max_file_mb: cfg.heuristics.max_file_mb,
    };

    let mut findings = Vec::new();
    for scan_root in paths {
        if scan_root.is_file() {
            findings.extend(rules.evaluate(scan_root));
            continue;
        }

        for entry in WalkDir::new(scan_root)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
        {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if glob_set.is_match(path) {
                continue;
            }
            findings.extend(rules.evaluate(path));
        }
    }

    Ok(findings)
}
