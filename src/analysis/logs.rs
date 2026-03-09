use std::collections::HashMap;
use std::path::Path;

use crate::types::LogAnomaly;

pub fn analyze(log_path: &Path) -> Vec<LogAnomaly> {
    let content = match std::fs::read_to_string(log_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("warn: cannot read {}: {e}", log_path.display());
            return vec![];
        }
    };

    let mut failed_by_ip: HashMap<String, Vec<String>> = HashMap::new();
    let mut failed_by_user: HashMap<String, usize> = HashMap::new();
    let mut accepted_logins: Vec<String> = Vec::new();
    let mut sudo_events: Vec<String> = Vec::new();
    let mut user_creation: Vec<String> = Vec::new();

    for line in content.lines() {
        if line.contains("Failed password for") {
            if let Some(ip) = extract_ip(line) {
                failed_by_ip.entry(ip).or_default().push(line.to_string());
            }
            if let Some(user) = extract_user_from_failed(line) {
                *failed_by_user.entry(user).or_default() += 1;
            }
        } else if line.contains("Accepted password for")
            || line.contains("Accepted publickey for")
        {
            accepted_logins.push(line.to_string());
        } else if line.contains("sudo:") && line.contains("COMMAND=") {
            sudo_events.push(line.to_string());
        } else if line.contains("useradd")
            || line.contains("adduser")
            || line.contains("new user:")
        {
            user_creation.push(line.to_string());
        }
    }

    let mut anomalies = Vec::new();

    // Brute-force detection: IPs with >= 10 failures
    let mut brute_ips: Vec<(String, usize)> = failed_by_ip
        .iter()
        .filter(|(_, lines)| lines.len() >= 10)
        .map(|(ip, lines)| (ip.clone(), lines.len()))
        .collect();
    brute_ips.sort_by(|a, b| b.1.cmp(&a.1));

    if !brute_ips.is_empty() {
        let total: usize = brute_ips.iter().map(|(_, c)| c).sum();
        anomalies.push(LogAnomaly {
            event_type: "brute_force.ssh".to_string(),
            description: format!(
                "{} source IPs with ≥10 failed SSH login attempts ({total} total failures)",
                brute_ips.len()
            ),
            count: total,
            examples: brute_ips
                .iter()
                .take(10)
                .map(|(ip, c)| format!("{ip}: {c} failures"))
                .collect(),
        });
    }

    // Users targeted frequently
    let mut targeted_users: Vec<(String, usize)> = failed_by_user
        .iter()
        .filter(|(_, &c)| c >= 5)
        .map(|(u, &c)| (u.clone(), c))
        .collect();
    targeted_users.sort_by(|a, b| b.1.cmp(&a.1));

    if !targeted_users.is_empty() {
        anomalies.push(LogAnomaly {
            event_type: "brute_force.users".to_string(),
            description: format!(
                "{} usernames targeted with ≥5 failed attempts",
                targeted_users.len()
            ),
            count: targeted_users.iter().map(|(_, c)| c).sum(),
            examples: targeted_users
                .iter()
                .take(10)
                .map(|(u, c)| format!("{u}: {c} failures"))
                .collect(),
        });
    }

    // Successful logins
    if !accepted_logins.is_empty() {
        anomalies.push(LogAnomaly {
            event_type: "auth.success".to_string(),
            description: format!("{} successful SSH logins", accepted_logins.len()),
            count: accepted_logins.len(),
            examples: accepted_logins.iter().rev().take(5).cloned().collect(),
        });
    }

    // Sudo usage
    if !sudo_events.is_empty() {
        anomalies.push(LogAnomaly {
            event_type: "privilege.sudo".to_string(),
            description: format!("{} sudo command executions", sudo_events.len()),
            count: sudo_events.len(),
            examples: sudo_events.iter().rev().take(5).cloned().collect(),
        });
    }

    // User account creation
    if !user_creation.is_empty() {
        anomalies.push(LogAnomaly {
            event_type: "account.creation".to_string(),
            description: format!("{} user account creation events", user_creation.len()),
            count: user_creation.len(),
            examples: user_creation.iter().take(5).cloned().collect(),
        });
    }

    anomalies
}

fn extract_ip(line: &str) -> Option<String> {
    // Matches: "... from <ip> port ..."
    let from_idx = line.find(" from ")?;
    let after = &line[from_idx + 6..];
    let end = after.find(" port ").or_else(|| after.find(' '))?;
    let candidate = after[..end].trim().to_string();
    // Rough validity check
    if candidate.contains('.') || candidate.contains(':') {
        Some(candidate)
    } else {
        None
    }
}

fn extract_user_from_failed(line: &str) -> Option<String> {
    // "Failed password for invalid user <name> from ..."
    // "Failed password for <name> from ..."
    if let Some(idx) = line.find("for invalid user ") {
        let after = &line[idx + 17..];
        let end = after.find(' ')?;
        return Some(after[..end].to_string());
    }
    if let Some(idx) = line.find("Failed password for ") {
        let after = &line[idx + 20..];
        let end = after.find(' ')?;
        return Some(after[..end].to_string());
    }
    None
}
