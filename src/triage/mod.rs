mod network;
mod persistence;
mod processes;

use chrono::Utc;

use crate::types::TriageReport;

pub fn collect() -> anyhow::Result<TriageReport> {
    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let processes = processes::collect();
    let connections = network::collect();
    let persistence = persistence::collect();

    Ok(TriageReport {
        timestamp: Utc::now().to_rfc3339(),
        hostname,
        processes,
        connections,
        persistence,
    })
}
