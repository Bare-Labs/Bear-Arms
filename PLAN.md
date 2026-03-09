# Bear-Arms Plan

As of March 2026.

## Mission

Bear-Arms is a **blue team cybersecurity toolkit** for macOS/Linux homelabs.
It is designed to serve **both humans (CLI) and agents (MCP server)** equally —
every capability is exposed as an MCP tool so that agents in the Bare Labs
ecosystem (BearClaw, Ursa, and others) can invoke them autonomously alongside
human operators.

---

## Architecture

```
bear-arms (single binary)
├── CLI subcommands          — humans use these directly
│   ├── doctor               validate config + watch paths
│   ├── scan                 file/hash/name/ext scanner with quarantine
│   ├── triage               process + network + persistence snapshot
│   ├── analyze              auth log anomaly detection
│   ├── harden               SSH / SUID / world-writable / passwd checks
│   └── serve                MCP server over stdio (agents use this)
│
└── MCP tools (serve mode)   — agents invoke these over JSON-RPC / stdio
    ├── scan
    ├── triage
    ├── analyze
    └── harden
```

The `serve` subcommand starts an MCP server on stdin/stdout using the
[rmcp](https://crates.io/crates/rmcp) SDK. Every CLI command maps 1:1 to an
MCP tool with structured JSON output so agents receive machine-readable results.

---

## Phase 0 — Foundations (done)

- [x] Rust CLI crate with YAML config loader
- [x] Rule-based file scanner (hash, name, extension, size)
- [x] Optional quarantine action
- [x] JSONL audit logging
- [x] Initial unit/integration tests

## Phase 1 — Blue Team Expansion (done)

- [x] `triage` command: running processes, open connections, persistence
- [x] `analyze` command: auth log parsing (brute force, sudo, account creation)
- [x] `harden` command: SSH config, SUID/SGID, world-writable, shadow, umask
- [x] Structured JSON output for all new commands

## Phase 2 — MCP Server (current)

- [x] `serve` subcommand starts rmcp server over stdio
- [x] All four capabilities exposed as MCP tools with JSON schema parameters
- [ ] MCP tool descriptions tuned for agent consumption
- [ ] `mcp.json` manifest for agent auto-discovery
- [ ] Integration test: spawn server, call tools via JSON-RPC, assert output shape

## Phase 3 — Detection Quality (Ursa-driven)

- [ ] Ursa-driven implant corpus for macOS and Linux test paths
- [ ] Deterministic detection regression harness
- [ ] Precision/recall tracking (target: ≥95% detection, ≤3% FP rate)
- [ ] Optional YARA-backed matcher module
- [ ] Benchmark fixture set for scan performance

## Phase 4 — Runtime Hardening

- [ ] Incremental scan index (mtime + hash cache) to avoid re-hashing unchanged files
- [ ] Watch mode with bounded CPU/IO budgets
- [ ] Tamper-evident audit chain (hash-linked JSONL events)
- [ ] Signed quarantine manifest + `restore` command

## Phase 5 — BearClaw Integration

- [ ] BearClaw policy hook contract for high-risk actions
- [ ] Approval gate for quarantine on sensitive paths
- [ ] AuthZ and policy enforcement tests
- [ ] Versioned API surface with contract tests

---

## MCP Tool Reference (serve mode)

| Tool      | Key Parameters                          | Returns                          |
|-----------|-----------------------------------------|----------------------------------|
| `scan`    | `path?`, `quarantine?`                  | JSON array of `Finding`          |
| `triage`  | *(none)*                                | JSON `TriageReport`              |
| `analyze` | `log_path?`                             | JSON array of `LogAnomaly`       |
| `harden`  | *(none)*                                | JSON array of `HardenFinding`    |

Start the MCP server:
```bash
bear-arms serve --config config/default.yaml
```

Add to an agent's MCP config (`mcp.json`):
```json
{
  "mcpServers": {
    "bear-arms": {
      "command": "bear-arms",
      "args": ["serve", "--config", "/path/to/config/default.yaml"]
    }
  }
}
```
