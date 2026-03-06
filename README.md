# Bear-Arms

Bear-Arms is a Rust-based antivirus/antimalware starter for macOS and Linux homelabs, intended to run alongside BearClaw.

## Current Starter Scope

- CLI commands:
  - `doctor`: validate config and watch paths
  - `scan`: run one-shot scanning with optional quarantine
- Rule-based detections:
  - known-bad SHA256 hashes
  - suspicious filenames
  - suspicious extensions (`.dylib`, `.so`, `.elf`, `.kext`)
  - oversized file anomaly check
- JSONL audit logging for all findings/actions

## Quickstart

```bash
cd Bear-Arms
cargo build
cargo run -- doctor --config config/default.yaml
cargo run -- scan --config config/default.yaml
```

Quarantine high-severity findings:

```bash
cargo run -- scan --config config/default.yaml --quarantine
```

## Ursa Validation Loop

Use Ursa to seed controlled implant artifacts in an isolated lab directory:
1. Seed artifacts with known expected detections.
2. Add expected hashes/names to `config/default.yaml`.
3. Run `scan --path <isolated-dir> --quarantine`.
4. Verify detection hit rate, false positives, and audit quality.
5. Promote rule updates only after repeatable test passes.

## Notes

- The previous Python scaffold has been retained in `legacy-python/` for reference.
- This starter is intentionally conservative and safe-by-default; destructive actions are limited to optional quarantine.
