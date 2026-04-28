"""
Trishula MCP Shield — Model Context Protocol Security Scanner
Detects unsafe STDIO transport defaults, missing authentication, exposed MCP
endpoints, and configuration weaknesses that enable the April 2026 RCE wave.

Zero dependencies. Air-gapped operation. SHA-256 attestation.
"""
import re, json, hashlib, os
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path

# ── Known Vulnerable MCP Configurations ──────────────────────────
UNSAFE_PATTERNS = {
    "STDIO_TRANSPORT_UNAUTH": {
        "pattern": r'transport\s*[=:]\s*["\']?stdio',
        "severity": "CRITICAL",
        "description": "STDIO transport without authentication — enables RCE via protocol injection",
        "cve_ref": "MCP-RCE-2026-04"
    },
    "MISSING_AUTH": {
        "pattern": r'(?:auth|authentication)\s*[=:]\s*["\']?(none|false|disabled|off)',
        "severity": "CRITICAL",
        "description": "Authentication explicitly disabled on MCP endpoint",
        "cve_ref": "MCP-RCE-2026-04"
    },
    "WILDCARD_CORS": {
        "pattern": r'(?:cors|allowed_origins)\s*[=:]\s*["\']?\*',
        "severity": "HIGH",
        "description": "Wildcard CORS allows any origin to interact with MCP server",
        "cve_ref": "MCP-CORS-2026"
    },
    "EXPOSED_TOOLS": {
        "pattern": r'(?:expose_tools|tool_access)\s*[=:]\s*["\']?(all|\*|true)',
        "severity": "HIGH",
        "description": "All tools exposed without granular access control",
        "cve_ref": "CSA-AGENT-2026"
    },
    "NO_RATE_LIMIT": {
        "pattern": r'(?:rate_limit|ratelimit)\s*[=:]\s*["\']?(0|none|false|disabled)',
        "severity": "MEDIUM",
        "description": "No rate limiting on MCP endpoint — DoS and brute-force risk",
        "cve_ref": "MCP-DOS-2026"
    },
    "DEBUG_MODE": {
        "pattern": r'(?:debug|verbose|trace)\s*[=:]\s*["\']?(true|on|enabled|1)',
        "severity": "MEDIUM",
        "description": "Debug mode enabled — may leak internal state to clients",
        "cve_ref": "MCP-INFO-2026"
    },
    "UNSAFE_DESERIALIZATION": {
        "pattern": r'(?:pickle|marshal|yaml\.unsafe_load|eval\s*\()',
        "severity": "CRITICAL",
        "description": "Unsafe deserialization detected — arbitrary code execution risk",
        "cve_ref": "LiteLLM-RCE-2026"
    },
    "HARDCODED_SECRET": {
        "pattern": r'(?:api_key|secret|token|password)\s*[=:]\s*["\'][A-Za-z0-9+/=]{16,}["\']',
        "severity": "HIGH",
        "description": "Hardcoded secret in MCP configuration file",
        "cve_ref": "CWE-798"
    },
    "BIND_ALL_INTERFACES": {
        "pattern": r'(?:host|bind|listen)\s*[=:]\s*["\']?0\.0\.0\.0',
        "severity": "HIGH",
        "description": "MCP server bound to all interfaces — accessible from network",
        "cve_ref": "MCP-EXPOSE-2026"
    },
    "LANGCHAIN_MCP": {
        "pattern": r'(?:from\s+langchain|import\s+langchain).*(?:mcp|tool)',
        "severity": "HIGH",
        "description": "LangChain MCP integration detected — affected by April 2026 RCE wave",
        "cve_ref": "MCP-RCE-2026-04"
    },
    "FLOWISE_MCP": {
        "pattern": r'(?:flowise|FlowiseAI).*(?:mcp|agent)',
        "severity": "HIGH",
        "description": "Flowise MCP integration detected — affected by April 2026 RCE wave",
        "cve_ref": "MCP-RCE-2026-04"
    },
    "LITELLM_IMPORT": {
        "pattern": r'(?:from\s+litellm|import\s+litellm)',
        "severity": "CRITICAL",
        "description": "LiteLLM dependency detected — supply chain compromised April 2026",
        "cve_ref": "LiteLLM-SUPPLY-2026"
    },
}

AFFECTED_FRAMEWORKS = {
    "langchain": "CRITICAL — MCP RCE confirmed",
    "litellm": "CRITICAL — Supply chain compromised (Mercor breach)",
    "flowise": "CRITICAL — MCP RCE confirmed",
    "lettaai": "HIGH — MCP RCE affected",
    "autogen": "MEDIUM — Uses MCP transport",
    "crewai": "MEDIUM — Agent framework, MCP-compatible",
}

@dataclass
class Finding:
    rule_id: str
    severity: str
    description: str
    file: str
    line: int
    match: str
    cve_ref: str

@dataclass
class ScanReport:
    scan_id: str
    timestamp: str
    files_scanned: int
    findings: list
    clean: bool
    attestation_hash: str
    framework_alerts: list

class MCPShield:
    def __init__(self):
        self._compiled = {}
        for rule_id, rule in UNSAFE_PATTERNS.items():
            self._compiled[rule_id] = re.compile(rule["pattern"], re.IGNORECASE)
        self._findings = []
        self._files_scanned = 0
        self._framework_alerts = []

    @property
    def pattern_count(self):
        return len(UNSAFE_PATTERNS)

    def reset(self):
        self._findings = []
        self._files_scanned = 0
        self._framework_alerts = []

    @staticmethod
    def redact(s, keep=4):
        if len(s) <= keep:
            return "****"
        return s[:keep] + "*" * (len(s) - keep)

    def scan_content(self, content, filename="<inline>"):
        findings = []
        for i, line in enumerate(content.split("\n"), 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            for rule_id, pattern in self._compiled.items():
                for m in pattern.finditer(line):
                    f = Finding(
                        rule_id=rule_id,
                        severity=UNSAFE_PATTERNS[rule_id]["severity"],
                        description=UNSAFE_PATTERNS[rule_id]["description"],
                        file=filename,
                        line=i,
                        match=self.redact(m.group(), 8),
                        cve_ref=UNSAFE_PATTERNS[rule_id]["cve_ref"]
                    )
                    findings.append(f)
                    self._findings.append(f)
        return findings

    def scan_file(self, filepath):
        path = Path(filepath)
        skip_ext = {".png", ".jpg", ".gif", ".ico", ".woff", ".ttf", ".pyc", ".exe", ".dll", ".so"}
        if path.suffix.lower() in skip_ext:
            return []
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            self._files_scanned += 1
            return self.scan_content(content, str(path))
        except (OSError, PermissionError):
            return []

    def scan_directory(self, dirpath, extensions=None):
        if extensions is None:
            extensions = {".py", ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".env", ".conf", ".ts", ".js"}
        findings = []
        for root, dirs, files in os.walk(dirpath):
            dirs[:] = [d for d in dirs if d not in {"node_modules", ".git", "__pycache__", "venv", ".venv"}]
            for f in files:
                if Path(f).suffix.lower() in extensions:
                    findings.extend(self.scan_file(os.path.join(root, f)))
        return findings

    def check_frameworks(self, content):
        alerts = []
        content_lower = content.lower()
        for fw, severity in AFFECTED_FRAMEWORKS.items():
            if fw in content_lower:
                alert = {"framework": fw, "severity": severity}
                alerts.append(alert)
                self._framework_alerts.append(alert)
        return alerts

    def check_requirements(self, filepath):
        alerts = []
        try:
            content = Path(filepath).read_text(encoding="utf-8", errors="ignore")
            for line in content.split("\n"):
                line = line.strip().lower()
                if line.startswith("#") or not line:
                    continue
                pkg = re.split(r'[>=<!\[\];\s]', line)[0]
                if pkg in AFFECTED_FRAMEWORKS:
                    alerts.append({"package": pkg, "severity": AFFECTED_FRAMEWORKS[pkg], "source": str(filepath)})
                    self._framework_alerts.append(alerts[-1])
        except (OSError, PermissionError):
            pass
        return alerts

    @staticmethod
    def shannon_entropy(s):
        if not s:
            return 0.0
        from collections import Counter
        import math
        freq = Counter(s)
        length = len(s)
        return -sum((c / length) * math.log2(c / length) for c in freq.values())

    def generate_report(self):
        findings_data = [{"rule": f.rule_id, "severity": f.severity, "file": f.file, "line": f.line} for f in self._findings]
        payload = json.dumps(findings_data, sort_keys=True)
        attestation = hashlib.sha256(payload.encode()).hexdigest()
        return ScanReport(
            scan_id=f"mcp_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            files_scanned=self._files_scanned,
            findings=self._findings,
            clean=len(self._findings) == 0,
            attestation_hash=attestation,
            framework_alerts=self._framework_alerts
        )

    def generate_attestation(self):
        report = self.generate_report()
        severity_breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self._findings:
            severity_breakdown[f.severity] = severity_breakdown.get(f.severity, 0) + 1
        return {
            "scan_id": report.scan_id,
            "timestamp": report.timestamp,
            "verdict": "CLEAN" if report.clean else "VULNERABLE",
            "total_findings": len(self._findings),
            "severity_breakdown": severity_breakdown,
            "framework_alerts": len(self._framework_alerts),
            "attestation_hash": report.attestation_hash
        }
