# Bear-Arms Blink Status

Bear-Arms does not currently have a project-local `blink.toml`.

## Current State

- Build: local Rust build via `cargo build`
- Test: local Rust test suite via `cargo test`
- Runtime posture: CLI-first tool, not a Blink-managed deployed service today

## What This Means

- There is no project-local Blink build, deploy, rollback, or verification pipeline yet.
- If Bear-Arms becomes a managed service or distributed tool later, add a project-local `blink.toml` and update this file to describe the real workflow.
