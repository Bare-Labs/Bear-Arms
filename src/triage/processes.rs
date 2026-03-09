use sysinfo::System;

use crate::types::ProcessInfo;

pub fn collect() -> Vec<ProcessInfo> {
    let sys = System::new_all();

    let mut procs: Vec<ProcessInfo> = sys
        .processes()
        .values()
        .map(|p| ProcessInfo {
            pid: p.pid().as_u32(),
            parent_pid: p.parent().map(|pid| pid.as_u32()),
            name: p.name().to_string_lossy().to_string(),
            exe: p.exe().map(|e| e.display().to_string()),
            cmdline: p
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().into_owned())
                .collect(),
        })
        .collect();

    procs.sort_by_key(|p| p.pid);
    procs
}
