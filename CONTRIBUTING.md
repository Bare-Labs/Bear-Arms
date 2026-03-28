# Contributing to Bear-Arms

## Setup

```bash
cargo build
cargo test
```

## Expectations

- Keep scanner behavior deterministic and auditable.
- Prefer machine-readable output for anything that may be consumed by agents.
- Update `README.md` for user-facing behavior changes.
- Update `SECURITY.md` when risk posture, quarantine semantics, or reporting guidance changes.
- Update `CHANGELOG.md` for shipped or meaningful in-progress work.

## Documentation Policy

Bear-Arms follows the shared BareSystems documentation contract. Active roadmap items live only in the workspace root `ROADMAP.md`.
