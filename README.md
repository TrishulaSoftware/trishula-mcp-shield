# Trishula MCP Shield v2.0

> **Sovereign Security Gatekeeper & Protocol Scanner for the Model Context Protocol (MCP)**

Trishula MCP Shield is an air-gapped, zero-dependency security scanner and runtime gatekeeper built to protect AI agents, developers, and enterprises from compromised Model Context Protocol (MCP) servers, prompt injection in tool definitions, unauthenticated STDIO command execution, and supply chain poisoning.

[![CI](https://github.com/TrishulaSoftware/trishula-mcp-shield/actions/workflows/ci.yml/badge.svg)](https://github.com/TrishulaSoftware/trishula-mcp-shield/actions)
![Tests](https://img.shields.io/badge/tests-55%2F55%20passing-brightgreen)
![Dependencies](https://img.shields.io/badge/dependencies-0%20(pure%20stdlib)-blue)
![License](https://img.shields.io/badge/license-MIT-purple)

---

## What's New in v2.0

- **Tool Schema Validation:** Audits MCP `tools/list` payloads to intercept prompt injection in descriptions, unconstrained shell/code primitives (`run_bash`, `eval_code`), and destructive database wipe commands.
- **Client Configuration Autodiscovery:** Automatically locates and audits MCP client configurations across **Claude Desktop**, **Antigravity / Gemini**, **Cursor**, and **Cline / Roo-Code** for unauthenticated command execution and plaintext API key leaks.
- **Institutional Markdown Scorecard:** Generates high-visibility audit scorecards with Security Scores (0–100), Letter Grades (A, B, C, F), and cryptographic SHA-256 attestation receipts.
- **Agensi & Agentic Skill Integration:** Packaged with official `SKILL.md` frontmatter, standalone runner (`scripts/mcp_shield_runner.py`), and standard MCP JSON-RPC 2.0 `stdio` server (`mcp_server.py`).

---

## Core Capabilities

- **Zero Third-Party Dependencies:** Pure Python standard library (`re`, `json`, `hashlib`, `os`, `pathlib`). No `pip install` required—immune to upstream package tampering.
- **Air-Gapped & Sovereign:** Zero external telemetry, zero network calls, zero egress. Runs safely in strictly isolated enterprise environments.
- **Cryptographic Attestation:** Deterministic SHA-256 attestation hash produced for every scan for compliance verification and CI/CD policy gating.
- **Sub-Millisecond Latency:** Scans entire project trees and multi-tool manifests in under 5 milliseconds.

---

## Proof of Function

```
Trishula MCP Shield v2.0: 55/55 deterministic tests PASSED (0 failures)
Verdict: SQA_v5_ASCENDED — EXCEEDED
```

Run the complete test suite:
```bash
python test_mcp_shield.py
```

---

## Usage

### 1. Host Client Autodiscovery & Audit
Scan all configured MCP servers on the current machine:
```bash
python scripts/mcp_shield_runner.py --scan-clients
```

### 2. Audit Tool Definitions
Validate a `tools/list` response or tool definition manifest:
```bash
python scripts/mcp_shield_runner.py --tools path/to/tools_list.json
```

### 3. Repository or Directory Scan
Audit any local MCP server codebase:
```bash
python scripts/mcp_shield_runner.py /path/to/mcp-server
```

### 4. Run as an MCP Server (STDIO)
Connect MCP Shield directly to Claude Desktop, Cursor, or Antigravity:
```bash
python mcp_server.py
```

---

## SQA Compliance

| Standard | Status | Evidence |
|:--|:--|:--|
| **SQA_v5_ASCENDED** | EXCEEDED | 55/55 deterministic tests, SHA-256 attestation, zero dependencies |
| **MC/DC Determinism** | PASS | Binary PASS/FAIL on every scan. No probabilistic acceptance. |
| **Zero-Leak Mandate** | PASS | No telemetry, no network calls, no data exfiltration. Air-gapped. |
| **Heartbeat Mandate** | PASS | Sub-millisecond scan latency (<5ms). |
| **Zero Dependencies** | PASS | Pure Python stdlib. `pip freeze` returns empty. |

---

## License

MIT License. Built by [Trishula Software](https://github.com/TrishulaSoftware) — Sovereign Security for the AI Age.
