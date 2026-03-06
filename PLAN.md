# Bear-Arms Plan

As of March 6, 2026.

## Mission

Build a Rust-native antivirus/antimalware platform for macOS/Linux homelabs that is auditable, policy-aware, and compatible with BearClaw orchestration.

## Phase 0 - Rust Foundations (current)

- [x] Create Rust CLI crate and baseline project structure
- [x] Add YAML config loader + rule-based scanner
- [x] Add optional quarantine action
- [x] Add JSONL audit logging
- [x] Add initial unit/integration tests
- [ ] Add benchmark fixture set for scan performance

## Phase 1 - Detection Quality (Ursa-driven)

- [ ] Build Ursa-driven implant corpus for macOS and Linux test paths
- [ ] Add deterministic detection regression harness
- [ ] Track precision/recall over known implant sets
- [ ] Add optional YARA-backed matcher module

Exit criteria:
- >= 95% detection on seeded implant corpus
- <= 3% false positive rate on clean baseline snapshots

## Phase 2 - Runtime Hardening

- [ ] Add incremental scan index (mtime + hash cache)
- [ ] Add watch mode with bounded CPU/IO budgets
- [ ] Add tamper-evident audit chain (hash-linked events)
- [ ] Add signed quarantine manifest and restore command

Exit criteria:
- Reproducible scan outcomes and stable runtime behavior
- Audit log supports forensic integrity checks

## Phase 3 - BearClaw Integration

- [ ] Define BearClaw policy hook contract for high-risk actions
- [ ] Add approval gate for quarantine on sensitive paths
- [ ] Publish read-only control/API surface first
- [ ] Add authz and policy enforcement tests

Exit criteria:
- Sensitive actions blocked without explicit policy approval
- Contracts versioned and test-covered
