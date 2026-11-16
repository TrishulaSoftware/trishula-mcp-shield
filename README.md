# Trishula MCP Shield v2.5 (SQA v5.2 Ascended)

> **Sovereign Security Gatekeeper, AST Verifier & Zero-RCE Firewall for the Model Context Protocol (MCP)**

Trishula MCP Shield is an air-gapped, zero-dependency security scanner, Python AST verifier, and runtime JSON-RPC 2.0 firewall built under **Trishula Doctrine & SQA v5.2 Ascended (`SQAV5A`)**. It protects AI agents, developers, and enterprises from compromised MCP servers, prompt injection in tool definitions, unauthenticated STDIO command execution, global RCE exploit waves (PHP2Shell, Node2Shell, x402 Drain), and supply chain poisoning.

[![CI](https://github.com/TrishulaSoftware/trishula-mcp-shield/actions/workflows/ci.yml/badge.svg)](https://github.com/TrishulaSoftware/trishula-mcp-shield/actions)
![Tests](https://img.shields.io/badge/tests-75%2F75%20passing-brightgreen)
![SQA](https://img.shields.io/badge/SQA-v5.2%20Ascended-purple)
![Dependencies](https://img.shields.io/badge/dependencies-0%20(pure%20stdlib)-blue)
![License](https://img.shields.io/badge/license-MIT-purple)

---

## SWOT Doctrinal Hardening Matrix (v2.5 Ascended)

| SWOT Mandate | Doctrinal / SQAV5A Upgrade | Verification |
| :--- | :--- | :--- |
| **Embolden Strengths** | Added **NIST FIPS 202 SHA3-512 Merkle Root** + **Domain-Separated HMAC-SHA3-512 Seal** (`TRISHULA-MCP-SHIELD-SQAV5A-V5.2`) alongside SHA-256 attestation. Zero dependencies (`pip freeze` = empty). | Category 6 & 11 (17/17 PASS) |
| **Eliminate Weaknesses** | Added **Deterministic Python AST Static Verification (`scan_python_ast`)** (`eval`, `exec`, `os.system`, `subprocess(shell=True)`, `pickle.loads`) + **Live Runtime JSON-RPC 2.0 Firewall (`intercept_jsonrpc_message`)** emitting `-32600 CRITICAL_HALT`. | Category 10 & 13 (9/9 PASS) |
| **Seize Opportunities** | Added **OASIS SARIF v2.1.0 Enterprise Output (`--sarif`)**, **GitHub Marketplace Action (`action.yml`)**, Agensi `SKILL.md`, and cross-registry manifests (`smithery.yaml`, `glama.json`, `server.json`, `clawhub.json`). | Category 7, 8, 9, 13 (18/18 PASS) |
| **Neutralize Threats** | Added **SQAV5A Pillar 3 Zero-RCE WAF** blocking PHP2Shell (`CVE-2026-109618`), Node2Shell (`CVE-2026-111497`), `x402://` wallet drain, `${jndi:...}`, Cloud SSRF (`169.254.169.254`), and **Pillar 4 Zero-Leak Egress Guard** (protected paths + Shannon entropy `H >= 4.2`). | Category 12 (8/8 PASS) |

---

## Proof of Function

```
Trishula MCP Shield v2.5: 75/75 deterministic tests PASSED (0 failures)
Verdict: SQA_v5_ASCENDED — EXCEEDED
```

Run the complete 13-category test suite:
```bash
python test_mcp_shield.py
```

---

## Usage

### 1. Host Client Autodiscovery & Audit
Scan all configured MCP servers on the current machine (Claude Desktop, Antigravity, Cursor, Cline):
```bash
python scripts/mcp_shield_runner.py --scan-clients
```

### 2. Audit Tool Definitions
Validate a `tools/list` response or tool definition manifest:
```bash
python scripts/mcp_shield_runner.py --tools path/to/tools_list.json
```

### 3. Repository Scan + Python AST Verification + SARIF v2.1.0 Export
Audit any local MCP server codebase and export SARIF for GitHub Code Scanning:
```bash
python mcp_shield.py /path/to/mcp-server --ast --sarif-out results.sarif
```

### 4. Run as an MCP Server (STDIO)
Connect MCP Shield directly to Claude Desktop, Cursor, or Antigravity:
```bash
python mcp_server.py
```

---

## SQA v5.2 Ascended Compliance

| Standard | Status | Evidence |
|:--|:--|:--|
| **SQA_v5.2_ASCENDED** | EXCEEDED | 75/75 deterministic tests across 13 categories, zero dependencies |
| **Pillar 1: Zero-Slop AST & Bytecode** | PASS | `ast.parse` call-sink verification + `py_compile` clean |
| **Pillar 2: Cryptographic Armor** | PASS | SHA-256 + SHA3-512 Merkle Root + HMAC-SHA3-512 seal |
| **Pillar 3: Zero-RCE WAF** | PASS | Blocks PHP2Shell, Node2Shell, x402 Drain, JNDI, SSRF, Traversal |
| **Pillar 4: Zero-Leak Egress** | PASS | Protected doctrinal path block + Shannon entropy (`H >= 4.2`) guard |
| **SEPTIP-L4 Docker Law** | PASS | Enforced `.dockerignore` excluding `.git`, `venv/`, `.env`, `backups/`, `receipts/` |

---

## License

MIT License. Built by [Trishula Software](https://github.com/TrishulaSoftware) — Sovereign Security for the AI Age.
