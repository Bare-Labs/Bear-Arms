use std::path::Path;

use walkdir::WalkDir;

use crate::types::PersistenceEntry;

pub fn collect() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();
    entries.extend(check_cron());
    entries.extend(check_systemd());
    entries.extend(check_shell_rc());
    entries
}

fn check_cron() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();

    let cron_paths = [
        "/etc/crontab",
        "/etc/cron.d",
        "/var/spool/cron",
        "/var/spool/cron/crontabs",
    ];

    for path_str in &cron_paths {
        let path = Path::new(path_str);

        if path.is_file() {
            if let Ok(content) = std::fs::read_to_string(path) {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    entries.push(PersistenceEntry {
                        kind: "cron".to_string(),
                        source: path_str.to_string(),
                        detail: trimmed.to_string(),
                    });
                }
            }
            continue;
        }

        if path.is_dir() {
            for entry in WalkDir::new(path)
                .max_depth(2)
                .into_iter()
                .filter_map(Result::ok)
                .filter(|e| e.path().is_file())
            {
                if let Ok(content) = std::fs::read_to_string(entry.path()) {
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if trimmed.is_empty() || trimmed.starts_with('#') {
                            continue;
                        }
                        entries.push(PersistenceEntry {
                            kind: "cron".to_string(),
                            source: entry.path().display().to_string(),
                            detail: trimmed.to_string(),
                        });
                    }
                }
            }
        }
    }

    entries
}

fn check_systemd() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();

    // Units in these dirs are user-managed (not package-installed defaults)
    let unit_dirs = ["/etc/systemd/system", "/usr/local/lib/systemd/system"];

    for dir in &unit_dirs {
        let path = Path::new(dir);
        if !path.is_dir() {
            continue;
        }

        for entry in WalkDir::new(path)
            .max_depth(2)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| {
                e.path().is_file()
                    && e.path()
                        .extension()
                        .and_then(|x| x.to_str())
                        .map(|x| x == "service" || x == "timer")
                        .unwrap_or(false)
            })
        {
            let unit_name = entry
                .path()
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();

            // Skip well-known distro-managed units (symlinks back to /lib/systemd)
            if entry.path().is_symlink() {
                continue;
            }

            entries.push(PersistenceEntry {
                kind: "systemd_unit".to_string(),
                source: entry.path().display().to_string(),
                detail: unit_name,
            });
        }
    }

    entries
}

fn check_shell_rc() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();

    // Collect home dirs from /etc/passwd
    let home_dirs = home_dirs_from_passwd();

    let rc_files = [
        ".bashrc",
        ".bash_profile",
        ".profile",
        ".zshrc",
        ".zprofile",
        ".bash_logout",
    ];

    for home in &home_dirs {
        for rc in &rc_files {
            let path = home.join(rc);
            if !path.is_file() {
                continue;
            }
            if let Ok(content) = std::fs::read_to_string(&path) {
                for line in content.lines() {
                    let trimmed = line.trim();
                    // Flag lines that look like they're executing something at startup
                    if trimmed.is_empty()
                        || trimmed.starts_with('#')
                        || trimmed.starts_with("export ")
                        || trimmed.starts_with("alias ")
                    {
                        continue;
                    }
                    entries.push(PersistenceEntry {
                        kind: "shell_rc".to_string(),
                        source: path.display().to_string(),
                        detail: trimmed.to_string(),
                    });
                }
            }
        }
    }

    entries
}

fn home_dirs_from_passwd() -> Vec<std::path::PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(content) = std::fs::read_to_string("/etc/passwd") {
        for line in content.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 6 {
                let home = Path::new(fields[5]);
                if home.starts_with("/home") || home.starts_with("/root") {
                    dirs.push(home.to_path_buf());
                }
            }
        }
    }
    dirs
}
