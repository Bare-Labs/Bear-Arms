use std::path::{Path, PathBuf};

use anyhow::Context;

pub fn quarantine_file(path: &Path, quarantine_dir: &Path) -> anyhow::Result<PathBuf> {
    std::fs::create_dir_all(quarantine_dir)
        .with_context(|| format!("failed to create quarantine dir {}", quarantine_dir.display()))?;

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!("invalid file name: {}", path.display()))?;

    let mut target = quarantine_dir.join(file_name);
    let mut suffix = 1;
    while target.exists() {
        target = quarantine_dir.join(format!("{}.{}", file_name, suffix));
        suffix += 1;
    }

    std::fs::rename(path, &target).with_context(|| {
        format!(
            "failed to move {} to {}",
            path.display(),
            target.as_path().display()
        )
    })?;

    Ok(target)
}
