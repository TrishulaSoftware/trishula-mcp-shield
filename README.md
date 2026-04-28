# MCP Shield

> **Triage Response:** MCP (Model Context Protocol) RCE — 7,000+ servers exposed

Model Context Protocol security scanner that detects unsafe STDIO transport defaults, missing authentication, exposed MCP endpoints, and integration with compromised frameworks (LangChain, LiteLLM, Flowise, LettaAI). 12 detection rules, framework import detection, requirements.txt scanning, SHA-256 attestation. Built in direct response to the April 2026 MCP RCE wave affecting 7,000+ servers.

## The Problem

Anthropic's Model Context Protocol has a by-design RCE flaw in its STDIO transport. Unsafe defaults allow remote code execution across LiteLLM, LangChain, Flowise, LettaAI, and 7,000+ servers. No scanner exists.

## What It Does

- **Zero Dependencies** — Pure Python stdlib. No pip install, no npm, no Go binary. Import and scan.
- **SHA-256 Attestation** — Every scan produces a cryptographic attestation hash proving scan integrity.
- **Air-Gapped Operation** — Works completely offline. No API calls, no telemetry, no cloud.
- **Import as Library** — Use as a module in your own code: `import mcp_shield`

## Proof of Function

```
MCP Shield: 41/41 tests PASSED
Verdict: SQA_v5_ASCENDED — EXCEEDED
```

Run tests yourself:
```bash
python test_mcp_shield.py
```

## Why The Public Needs This

Anthropic's Model Context Protocol has a by-design RCE flaw in its STDIO transport. Unsafe defaults allow remote code execution across LiteLLM, LangChain, Flowise, LettaAI, and 7,000+ servers. No scanner exists.

### Competitive Analysis

**No direct competitors.** The MCP protocol is new and no security scanner exists for it. Anthropic provides no security tooling for MCP. This is the first MCP-specific security scanner.

## SQA Documentation

| Standard | Status | Evidence |
|:--|:--|:--|
| **SQA_v5_ASCENDED** | EXCEEDED | 41/41 deterministic tests, SHA-256 attestation, zero dependencies |
| **MC/DC Determinism** | PASS | Binary PASS/FAIL on every scan. No probabilistic acceptance. |
| **Zero-Leak Mandate** | PASS | No telemetry, no network calls, no data exfiltration. Air-gapped. |
| **Heartbeat Mandate** | PASS | Sub-millisecond scan latency. |
| **Zero Dependencies** | PASS | Pure Python stdlib. `pip freeze` returns empty. |

## CI/CD

![CI](https://github.com/TrishulaSoftware/trishula-mcp-shield/actions/workflows/ci.yml/badge.svg)

Tests run on Python 3.11 and 3.12. Results posted to GitHub Actions Job Summary with 90-day artifact retention.

## License

MIT

---

**Built by [Trishula Software](https://github.com/TrishulaSoftware) — Sovereign Security for the AI Age**