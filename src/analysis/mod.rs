pub mod logs;

use std::path::{Path, PathBuf};

use crate::types::LogAnomaly;

/// Returns the default auth log path for the current distro.
pub fn default_log_path() -> PathBuf {
    // Debian/Ubuntu
    let debian = Path::new("/var/log/auth.log");
    if debian.exists() {
        return debian.to_path_buf();
    }
    // RHEL/CentOS/Fedora
    PathBuf::from("/var/log/secure")
}

pub fn run(log_path: &Path) -> Vec<LogAnomaly> {
    logs::analyze(log_path)
}
