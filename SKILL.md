---
name: trishula-mcp-shield
description: "Audits, intercepts, and sanitizes Model Context Protocol (MCP) server configurations, tool schemas, Python AST sinks, and live JSON-RPC payloads against prompt injection, Zero-RCE exploits (PHP2Shell, Node2Shell, x402 Drain, JNDI, SSRF), and supply chain poisoning with SHA-256 + SHA3-512 Merkle Root cryptographic attestation."
---

# Trishula MCP Shield v2.5 (SQAV5A Ascended): Protocol Security Scanner & Zero-RCE Gatekeeper

**MCP Shield** is an air-gapped, zero-dependency security scanner, AST verifier, and runtime JSON-RPC firewall (`https://github.com/TrishulaSoftware/trishula-mcp-shield`) engineered under **Trishula Doctrine & SQA v5.2 Ascended (`SQAV5A`)**. It protects AI coding agents and local developers from compromised MCP servers, prompt injection in tool descriptions, unauthenticated STDIO command execution, and supply chain poisoning.

---

## When to Trigger This Skill

Activate this skill whenever:
1. **Adding or Registering New MCP Servers:** Before connecting any third-party MCP server or plugin to Claude Desktop, Cursor, Gemini, or Antigravity.
2. **Auditing Registered Tools & Live Calls:** Whenever an agent inspects an MCP `tools/list` manifest or intercepts a `tools/call` JSON-RPC 2.0 frame.
3. **Running CI/CD & Compliance Sweeps:** Prior to merging MCP server code, generating OASIS SARIF v2.1.0 reports, or verifying cryptographic Merkle root receipts.
4. **Triggered by Slash Commands:** When the user issues `/mcp-audit`, `/shield`, or asks *"are my MCP servers safe?"*

---

## Operational Execution Modes

### Mode 1: Host Client Config Autodiscovery & Audit
Scans all standard local MCP client configurations across the operating system (Claude Desktop, Antigravity, Cursor, Cline):

```bash
python scripts/mcp_shield_runner.py --scan-clients
```

### Mode 2: Tool Schema & Prompt Injection Validation
Audits an MCP server's exposed tool definitions or JSON manifest against prompt injection and dangerous execution primitives:

```bash
python scripts/mcp_shield_runner.py --tools path/to/tools_list.json
```

### Mode 3: Full Codebase + Python AST + SARIF v2.1.0 Audit
Audits an MCP server repository using regex rules AND deterministic Python Abstract Syntax Tree (`ast.parse`) call-sink analysis:

```bash
python mcp_shield.py /path/to/mcp-server --ast --sarif-out results.sarif
```

### Mode 4: Live Runtime JSON-RPC 2.0 Firewall (`mcp_intercept_jsonrpc`)
Inspects live JSON-RPC frames in-flight via the bundled MCP server (`python mcp_server.py`) against:
- **PHP2Shell (`CVE-2026-109618`):** `php://`, `phar://`, `expect://`, `allow_url_include`
- **Node2Shell (`CVE-2026-111497`):** `__proto__`, `constructor.prototype`, `child_process`, Brotli bombs
- **x402 Wallet Drain:** `x402://`, `drain_wallet`, unauthorized transaction signing prompts
- **JNDI & Cloud SSRF:** `${jndi:ldap://...}`, `169.254.169.254`, `metadata.google.internal`
- **Zero-Leak Egress Boundary:** Hard block on sovereign files (`.env`, `Aegis-Systems/`, `pulse_law.md`, `receipts/`, `backups/`) and Shannon entropy (`H >= 4.2`) secret leakage.

---

## Cryptographic Verification & Output Standard

Every scan generates an SQAV5A attestation receipt sealed with **SHA-256**, **NIST FIPS 202 SHA3-512 Merkle Root**, and **HMAC-SHA3-512**:
```json
{
  "scan_id": "mcp_20261116T030800",
  "sqa_standard": "SQA_v5.2_ASCENDED",
  "verdict": "CLEAN",
  "score": 100,
  "grade": "A",
  "total_findings": 0,
  "attestation_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "sha3_512_merkle_root": "6226252f8c6a6d0d...",
  "hmac_sha3_512_seal": "9a8f1b3c4d5e6f70..."
}
```

*Enforce strict Zero-Tolerance:* If the audit verdict is **Grade F** or findings contain any `CRITICAL` severity item, the agent must quarantine the target MCP server (`CRITICAL_HALT`) and halt execution until the user explicitly authorizes remediation.

