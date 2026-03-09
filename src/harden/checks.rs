use std::path::Path;

use walkdir::WalkDir;

use crate::types::{HardenFinding, HardenSeverity};

pub fn run_all() -> Vec<HardenFinding> {
    let mut findings = Vec::new();
    findings.extend(check_ssh_config());
    findings.extend(check_suid_sgid());
    findings.extend(check_world_writable());
    findings.extend(check_passwd_shadowed());
    findings.extend(check_umask());
    findings
}

fn check_ssh_config() -> Vec<HardenFinding> {
    let config_path = "/etc/ssh/sshd_config";
    let content = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(_) => {
            return vec![HardenFinding {
                check_id: "ssh.config_unreadable".to_string(),
                severity: HardenSeverity::Info,
                description: "sshd_config not found or unreadable".to_string(),
                detail: format!("{config_path} could not be read"),
                remediation: "Ensure SSH is installed and sshd_config is accessible".to_string(),
            }]
        }
    };

    let mut findings = Vec::new();
    let effective_lines: Vec<&str> = content
        .lines()
        .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
        .collect();

    let get_val = |key: &str| -> Option<String> {
        effective_lines
            .iter()
            .find(|l| l.to_lowercase().starts_with(&key.to_lowercase()))
            .and_then(|l| l.split_whitespace().nth(1))
            .map(|v| v.to_lowercase())
    };

    // PermitRootLogin
    match get_val("PermitRootLogin").as_deref() {
        None | Some("yes") => findings.push(HardenFinding {
            check_id: "ssh.permit_root_login".to_string(),
            severity: HardenSeverity::Critical,
            description: "SSH permits direct root login".to_string(),
            detail: "PermitRootLogin is 'yes' or not set (defaults to yes on some distros)"
                .to_string(),
            remediation: "Set 'PermitRootLogin no' in /etc/ssh/sshd_config".to_string(),
        }),
        _ => {}
    }

    // PasswordAuthentication
    match get_val("PasswordAuthentication").as_deref() {
        None | Some("yes") => findings.push(HardenFinding {
            check_id: "ssh.password_auth".to_string(),
            severity: HardenSeverity::Warning,
            description: "SSH allows password-based authentication".to_string(),
            detail: "PasswordAuthentication is enabled; brute-force attacks are possible"
                .to_string(),
            remediation:
                "Set 'PasswordAuthentication no' and use key-based authentication instead"
                    .to_string(),
        }),
        _ => {}
    }

    // Protocol version (old sshd configs)
    if let Some(proto) = get_val("Protocol") {
        if proto == "1" {
            findings.push(HardenFinding {
                check_id: "ssh.protocol_v1".to_string(),
                severity: HardenSeverity::Critical,
                description: "SSH configured to allow protocol version 1".to_string(),
                detail: "Protocol 1 is cryptographically broken".to_string(),
                remediation: "Set 'Protocol 2' or remove the Protocol directive".to_string(),
            });
        }
    }

    // X11Forwarding
    if get_val("X11Forwarding").as_deref() == Some("yes") {
        findings.push(HardenFinding {
            check_id: "ssh.x11_forwarding".to_string(),
            severity: HardenSeverity::Warning,
            description: "SSH X11 forwarding is enabled".to_string(),
            detail: "X11 forwarding increases attack surface if clients are compromised"
                .to_string(),
            remediation: "Set 'X11Forwarding no' unless X11 forwarding is required".to_string(),
        });
    }

    findings
}

#[cfg(unix)]
fn check_suid_sgid() -> Vec<HardenFinding> {
    use std::os::unix::fs::PermissionsExt;

    let scan_dirs = [
        "/usr/bin",
        "/usr/sbin",
        "/bin",
        "/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
    ];

    let mut suid: Vec<String> = Vec::new();
    let mut sgid: Vec<String> = Vec::new();

    for dir in &scan_dirs {
        let path = Path::new(dir);
        if !path.is_dir() {
            continue;
        }
        for entry in WalkDir::new(path)
            .max_depth(1)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| e.path().is_file())
        {
            if let Ok(meta) = entry.metadata() {
                let mode = meta.permissions().mode();
                if mode & 0o4000 != 0 {
                    suid.push(entry.path().display().to_string());
                } else if mode & 0o2000 != 0 {
                    sgid.push(entry.path().display().to_string());
                }
            }
        }
    }

    let mut findings = Vec::new();

    if !suid.is_empty() {
        findings.push(HardenFinding {
            check_id: "fs.suid_binaries".to_string(),
            severity: HardenSeverity::Info,
            description: format!("{} SUID binaries found in standard bin directories", suid.len()),
            detail: suid.join(", "),
            remediation:
                "Audit each binary; remove the SUID bit with 'chmod u-s <file>' if not required"
                    .to_string(),
        });
    }

    if !sgid.is_empty() {
        findings.push(HardenFinding {
            check_id: "fs.sgid_binaries".to_string(),
            severity: HardenSeverity::Info,
            description: format!("{} SGID binaries found in standard bin directories", sgid.len()),
            detail: sgid.join(", "),
            remediation:
                "Audit each binary; remove the SGID bit with 'chmod g-s <file>' if not required"
                    .to_string(),
        });
    }

    findings
}

#[cfg(not(unix))]
fn check_suid_sgid() -> Vec<HardenFinding> {
    vec![]
}

#[cfg(unix)]
fn check_world_writable() -> Vec<HardenFinding> {
    use std::os::unix::fs::PermissionsExt;

    let scan_dirs = ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin"];
    let mut writable: Vec<String> = Vec::new();

    for dir in &scan_dirs {
        let path = Path::new(dir);
        if !path.is_dir() {
            continue;
        }
        for entry in WalkDir::new(path)
            .max_depth(3)
            .into_iter()
            .filter_map(Result::ok)
        {
            // Skip symlinks — their permissions are on the target
            if entry.path_is_symlink() {
                continue;
            }
            if let Ok(meta) = entry.metadata() {
                if meta.permissions().mode() & 0o002 != 0 {
                    writable.push(entry.path().display().to_string());
                }
            }
        }
    }

    if writable.is_empty() {
        return vec![];
    }

    vec![HardenFinding {
        check_id: "fs.world_writable".to_string(),
        severity: HardenSeverity::Warning,
        description: format!(
            "{} world-writable paths found in sensitive directories",
            writable.len()
        ),
        detail: writable.join(", "),
        remediation: "Remove world-write permission: 'chmod o-w <path>'".to_string(),
    }]
}

#[cfg(not(unix))]
fn check_world_writable() -> Vec<HardenFinding> {
    vec![]
}

fn check_passwd_shadowed() -> Vec<HardenFinding> {
    let mut findings = Vec::new();

    // Check if any accounts in /etc/passwd have a non-'x' or non-'*' password field
    if let Ok(content) = std::fs::read_to_string("/etc/passwd") {
        let unshadowed: Vec<String> = content
            .lines()
            .filter(|l| {
                let fields: Vec<&str> = l.split(':').collect();
                if fields.len() < 2 {
                    return false;
                }
                let pw = fields[1];
                pw != "x" && pw != "*" && pw != "!" && !pw.is_empty()
            })
            .map(|l| l.split(':').next().unwrap_or("").to_string())
            .collect();

        if !unshadowed.is_empty() {
            findings.push(HardenFinding {
                check_id: "auth.passwd_not_shadowed".to_string(),
                severity: HardenSeverity::Critical,
                description: format!(
                    "{} accounts have password hashes directly in /etc/passwd",
                    unshadowed.len()
                ),
                detail: format!("Accounts: {}", unshadowed.join(", ")),
                remediation: "Run 'pwconv' to migrate passwords to /etc/shadow".to_string(),
            });
        }
    }

    findings
}

fn check_umask() -> Vec<HardenFinding> {
    // Check /etc/login.defs for UMASK setting
    let mut findings = Vec::new();

    if let Ok(content) = std::fs::read_to_string("/etc/login.defs") {
        let umask_val = content
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .find(|l| l.trim_start().to_uppercase().starts_with("UMASK"))
            .and_then(|l| l.split_whitespace().nth(1))
            .map(|v| v.to_string());

        if let Some(umask) = umask_val {
            // Permissive umask like 022 is fine; 000 or 002 is risky
            if umask == "000" || umask == "002" {
                findings.push(HardenFinding {
                    check_id: "auth.permissive_umask".to_string(),
                    severity: HardenSeverity::Warning,
                    description: format!("Default umask is permissive: {umask}"),
                    detail: format!("UMASK={umask} in /etc/login.defs"),
                    remediation: "Set 'UMASK 027' or stricter in /etc/login.defs".to_string(),
                });
            }
        }
    }

    findings
}
