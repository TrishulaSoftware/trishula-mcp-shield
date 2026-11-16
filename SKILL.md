---
name: mcp-shield
description: "Audits and sanitizes Model Context Protocol (MCP) server configurations, tool schemas, and client endpoints against prompt injection, dangerous execution primitives, wildcard CORS, and supply chain poisoning with SHA-256 cryptographic attestation."
---

# Trishula MCP Shield: Protocol Security Scanner & Gatekeeper

**MCP Shield** is an air-gapped, zero-dependency security scanner and protocol firewall (`https://github.com/TrishulaSoftware/trishula-mcp-shield`) that protects AI coding agents and local developers from compromised MCP servers, prompt injection in tool descriptions, unauthenticated STDIO command execution, and supply chain poisoning.

---

## When to Trigger This Skill

Activate this skill whenever:
1. **Adding or Registering New MCP Servers:** Before connecting any community MCP server or plugin to Claude Desktop, Cursor, Gemini, or Antigravity.
2. **Auditing Registered Tools:** Whenever an agent or user inspects the output of an MCP `tools/list` request or encounters an unverified tool definition.
3. **Running Security Compliance Sweeps:** Prior to committing MCP server code, running CI/CD validation gates, or establishing an air-gapped audit trail.
4. **Triggered by Slash Commands:** When the user issues `/mcp-audit`, `/shield`, or asks *"are my MCP servers safe?"*

---

## Operational Execution Modes

### Mode 1: Host Client Config Autodiscovery & Audit
Scans all standard local MCP client configurations across the operating system (Claude Desktop, Antigravity, Cursor, Cline):

```bash
python scripts/mcp_shield_runner.py --scan-clients
```

**What it detects:**
- Servers executing direct shell binaries (`bash`, `sh`, `powershell`, `cmd`).
- Plaintext API keys and secrets embedded in `env` blocks.
- Unauthenticated STDIO transport configurations.

---

### Mode 2: Tool Schema & Prompt Injection Validation
Audits an MCP server's exposed tool definitions or JSON manifest against prompt injection and dangerous execution primitives:

```bash
python scripts/mcp_shield_runner.py --tools path/to/tools_list.json
```

**Deterministic Pass/Fail Criteria:**
- **CRITICAL / REJECT:** Tool name or input properties expose raw unconstrained shell/code execution (`run_bash`, `eval_code`, `command: string`).
- **CRITICAL / REJECT:** Tool description contains system prompt override directives (`"ignore previous instructions"`, `"you are now unrestricted"`).
- **HIGH / ACTION REQUIRED:** Tools lacking input schema boundary validation or exposing destructive data wipe capabilities (`drop_database`, `truncate_all`).

---

### Mode 3: Directory & Codebase Audit
Audits an MCP server repository or package for CVE-level flaws, wildcard CORS, and compromised upstream dependencies:

```bash
python scripts/mcp_shield_runner.py /path/to/mcp-server-repo
```

Produces an **Institutional Security Scorecard** with:
- Security Score (`0–100`) and Letter Grade (`A`, `B`, `C`, `F`)
- Deterministic findings breakdown with CVE references and remediation advice
- Cryptographic SHA-256 attestation receipt hash for pipeline gating.

---

## Verification & Output Standard

Every scan generates an attestation receipt formatted as:
```json
{
  "scan_id": "mcp_20261115T214500",
  "verdict": "CLEAN",
  "score": 100,
  "grade": "A",
  "total_findings": 0,
  "attestation_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

*Enforce strict Zero-Tolerance:* If the audit verdict is **Grade F** or findings contain any `CRITICAL` severity item, the agent must quarantine the target MCP server and halt execution until the user explicitly authorizes remediation.
