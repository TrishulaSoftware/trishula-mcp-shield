"""
Trishula MCP Shield v2.0 — Model Context Protocol Security Scanner & Gatekeeper
Detects unsafe STDIO transport defaults, missing authentication, exposed MCP
endpoints, prompt injection in tool descriptions, dangerous tool schema capabilities,
and client configuration weaknesses.

Zero dependencies. Air-gapped operation. SHA-256 attestation.
"""
import re, json, hashlib, os, sys
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Union
from pathlib import Path

# ── Category A: Known Vulnerable MCP Code & Config Patterns ───────
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

# ── Category B: Tool Schema Dangerous Capability Rules ───────────
DANGEROUS_TOOL_NAME_PATTERNS = [
    (r'(?:eval|execute|exec|run)_(?:code|python|bash|cmd|script|command)', "CRITICAL", "Arbitrary Code/Command Execution Tool", "CWE-94"),
    (r'(?:bash|shell|cmd|powershell|terminal|run_command)', "CRITICAL", "Unrestricted Host Shell Access", "CWE-78"),
    (r'(?:delete_all|drop_database|drop_table|truncate|wipe|purge_all)', "HIGH", "Destructive Data Deletion Tool", "CWE-284"),
    (r'(?:download_file|upload_file|write_raw_file|arbitrary_write)', "HIGH", "Unconstrained Filesystem Read/Write Tool", "CWE-22"),
    (r'(?:execute_raw_sql|run_sql|sql_query)', "HIGH", "Direct Unsanitized SQL Query Tool", "CWE-89"),
    (r'(?:exfiltrate|send_raw_http|http_post|tunnel_request)', "MEDIUM", "Out-of-band Network Egress Capability", "CWE-918")
]

PROMPT_INJECTION_PATTERNS = [
    (r'ignore\s+(?:previous|all|above)\s+instructions', "CRITICAL", "Prompt Injection: System Prompt Override in Tool Description", "OWASP-ASI-01"),
    (r'you\s+are\s+now\s+(?:unrestricted|dan|jailbreak|evil|free)', "CRITICAL", "Prompt Injection: Persona Hijacking in Tool Description", "OWASP-ASI-01"),
    (r'(?:system\s+prompt|hidden\s+directive|do\s+not\s+tell\s+the\s+user)', "HIGH", "Suspicious Covert Directive in Tool Schema", "OWASP-ASI-01"),
    (r'(?:base64\s+decode|rot13|eval\s*\(|atob\s*\()', "HIGH", "Obfuscated Payload Indicator in Tool Description", "CWE-116")
]

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
    findings: List[Finding]
    clean: bool
    attestation_hash: str
    framework_alerts: List[Dict[str, Any]]
    score: int = 100
    grade: str = "A"
    tool_schemas_scanned: int = 0
    client_configs_scanned: int = 0

class MCPShield:
    def __init__(self):
        self._compiled = {}
        for rule_id, rule in UNSAFE_PATTERNS.items():
            self._compiled[rule_id] = re.compile(rule["pattern"], re.IGNORECASE)
        self._tool_compiled = [(re.compile(p, re.IGNORECASE), sev, desc, cve) for p, sev, desc, cve in DANGEROUS_TOOL_NAME_PATTERNS]
        self._injection_compiled = [(re.compile(p, re.IGNORECASE), sev, desc, cve) for p, sev, desc, cve in PROMPT_INJECTION_PATTERNS]
        self._findings: List[Finding] = []
        self._files_scanned = 0
        self._tool_schemas_scanned = 0
        self._client_configs_scanned = 0
        self._framework_alerts: List[Dict[str, Any]] = []

    @property
    def pattern_count(self):
        return len(UNSAFE_PATTERNS)

    def reset(self):
        self._findings = []
        self._files_scanned = 0
        self._tool_schemas_scanned = 0
        self._client_configs_scanned = 0
        self._framework_alerts = []

    @staticmethod
    def redact(s: str, keep: int = 4) -> str:
        if len(s) <= keep:
            return "****"
        return s[:keep] + "*" * (len(s) - keep)

    def scan_content(self, content: str, filename: str = "<inline>") -> List[Finding]:
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

    def scan_file(self, filepath: Union[str, Path]) -> List[Finding]:
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

    def scan_directory(self, dirpath: Union[str, Path], extensions=None) -> List[Finding]:
        if extensions is None:
            extensions = {".py", ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".env", ".conf", ".ts", ".js"}
        findings = []
        for root, dirs, files in os.walk(dirpath):
            dirs[:] = [d for d in dirs if d not in {"node_modules", ".git", "__pycache__", "venv", ".venv"}]
            for f in files:
                if Path(f).suffix.lower() in extensions:
                    findings.extend(self.scan_file(os.path.join(root, f)))
        return findings

    def check_frameworks(self, content: str) -> List[Dict[str, str]]:
        alerts = []
        content_lower = content.lower()
        for fw, severity in AFFECTED_FRAMEWORKS.items():
            if fw in content_lower:
                alert = {"framework": fw, "severity": severity}
                alerts.append(alert)
                self._framework_alerts.append(alert)
        return alerts

    def check_requirements(self, filepath: Union[str, Path]) -> List[Dict[str, str]]:
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

    # ── Category C: Tool Schema Validation ───────────────────────────
    def scan_tool_schema(self, tool_def: Dict[str, Any], source_label: str = "<mcp_tool>") -> List[Finding]:
        """
        Audits a single MCP tool definition (name, description, inputSchema).
        Detects dangerous tool capabilities, unconstrained parameters, and prompt injection payloads.
        """
        findings = []
        self._tool_schemas_scanned += 1
        name = str(tool_def.get("name", ""))
        desc = str(tool_def.get("description", ""))
        schema = tool_def.get("inputSchema", {}) or {}

        # 1. Audit Tool Name for dangerous host execution / destruction
        for pattern, sev, desc_label, cve in self._tool_compiled:
            if pattern.search(name):
                f = Finding(
                    rule_id=f"DANGEROUS_TOOL_{pattern.pattern[:16].upper().replace('^', '').replace('(', '')}",
                    severity=sev,
                    description=f"{desc_label} (Tool: '{name}')",
                    file=source_label,
                    line=1,
                    match=self.redact(name, 8),
                    cve_ref=cve
                )
                findings.append(f)
                self._findings.append(f)

        # 2. Audit Tool Description for prompt injection or covert directives
        for pattern, sev, desc_label, cve in self._injection_compiled:
            m = pattern.search(desc)
            if m:
                f = Finding(
                    rule_id="TOOL_PROMPT_INJECTION",
                    severity=sev,
                    description=f"{desc_label} detected in description of '{name}'",
                    file=source_label,
                    line=1,
                    match=self.redact(m.group(), 8),
                    cve_ref=cve
                )
                findings.append(f)
                self._findings.append(f)

        # 3. Audit inputSchema for unconstrained input risks
        if isinstance(schema, dict):
            props = schema.get("properties", {})
            required = schema.get("required", [])
            for prop_name, prop_spec in props.items():
                p_name_lower = str(prop_name).lower()
                # Check for high-risk execution parameters
                if p_name_lower in {"code", "command", "cmd", "bash", "shell", "eval", "script", "sql"}:
                    f = Finding(
                        rule_id="UNCONSTRAINED_EXEC_PARAM",
                        severity="HIGH",
                        description=f"Tool '{name}' exposes raw execution parameter '{prop_name}'",
                        file=source_label,
                        line=1,
                        match=f"{name}.inputSchema.{prop_name}",
                        cve_ref="CWE-78"
                    )
                    findings.append(f)
                    self._findings.append(f)

                # Check if property has description with prompt injection
                if isinstance(prop_spec, dict):
                    prop_desc = str(prop_spec.get("description", ""))
                    for pattern, sev, desc_label, cve in self._injection_compiled:
                        m = pattern.search(prop_desc)
                        if m:
                            f = Finding(
                                rule_id="PARAM_PROMPT_INJECTION",
                                severity=sev,
                                description=f"Prompt injection pattern in param '{prop_name}' description of tool '{name}'",
                                file=source_label,
                                line=1,
                                match=self.redact(m.group(), 8),
                                cve_ref=cve
                            )
                            findings.append(f)
                            self._findings.append(f)

        return findings

    def scan_tools_list(self, tools_data: Union[List[Dict[str, Any]], Dict[str, Any]], source_label: str = "<mcp_tools_list>") -> List[Finding]:
        """
        Audits an MCP tools/list response dictionary or list of tool definitions.
        """
        tools = []
        if isinstance(tools_data, dict):
            tools = tools_data.get("tools", [])
        elif isinstance(tools_data, list):
            tools = tools_data

        findings = []
        for t in tools:
            if isinstance(t, dict):
                findings.extend(self.scan_tool_schema(t, source_label=source_label))
        return findings

    # ── Category D: Client Configuration Autodiscovery ───────────────
    @staticmethod
    def get_standard_config_locations() -> List[Dict[str, Any]]:
        """
        Returns list of well-known client configuration paths across platforms.
        """
        home = Path.home()
        appdata = os.environ.get("APPDATA")
        paths = []

        # 1. Claude Desktop
        if appdata:
            paths.append({
                "client": "Claude Desktop (Windows)",
                "path": Path(appdata) / "Claude" / "claude_desktop_config.json"
            })
        paths.append({
            "client": "Claude Desktop (macOS)",
            "path": home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
        })
        paths.append({
            "client": "Claude Desktop (Linux)",
            "path": home / ".config" / "Claude" / "claude_desktop_config.json"
        })

        # 2. Antigravity / Gemini MCP Directories
        gemini_dir = home / ".gemini" / "antigravity" / "mcp"
        paths.append({
            "client": "Antigravity MCP Storage",
            "path": gemini_dir
        })

        # 3. Cursor MCP Configs
        paths.append({
            "client": "Cursor User Config",
            "path": home / ".cursor" / "mcp.json"
        })
        paths.append({
            "client": "Cursor Workspace Config",
            "path": Path(".cursor") / "mcp.json"
        })

        # 4. Cline / Roo-Code MCP Config
        if appdata:
            paths.append({
                "client": "Cline / Roo-Code Config",
                "path": Path(appdata) / "Code" / "User" / "globalStorage" / "rooveterinaryinc.roo-cline" / "settings" / "cline_mcp_settings.json"
            })

        return paths

    def discover_and_scan_client_configs(self) -> List[Finding]:
        """
        Auto-scans all present standard MCP client configurations on the host.
        """
        findings = []
        discovered = self.get_standard_config_locations()
        for item in discovered:
            p: Path = item["path"]
            client_name = item["client"]
            if p.exists():
                self._client_configs_scanned += 1
                if p.is_file():
                    # Scan raw content for secrets and transport leaks
                    findings.extend(self.scan_file(p))
                    # Parse JSON structure to inspect servers
                    try:
                        data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
                        servers = data.get("mcpServers", {}) or {}
                        for s_name, s_spec in servers.items():
                            if isinstance(s_spec, dict):
                                cmd = s_spec.get("command", "")
                                args = s_spec.get("args", [])
                                env = s_spec.get("env", {}) or {}
                                # Check for command risks
                                if cmd in {"sh", "bash", "cmd", "powershell"}:
                                    f = Finding(
                                        rule_id="CLIENT_SHELL_COMMAND",
                                        severity="CRITICAL",
                                        description=f"Client '{client_name}' server '{s_name}' directly executes raw shell '{cmd}'",
                                        file=str(p),
                                        line=1,
                                        match=f"command: {cmd}",
                                        cve_ref="CWE-78"
                                    )
                                    findings.append(f)
                                    self._findings.append(f)
                                # Check env for hardcoded plaintext API keys
                                for k, v in env.items():
                                    v_str = str(v)
                                    if len(v_str) >= 20 and not v_str.startswith("$") and not v_str.startswith("%"):
                                        f = Finding(
                                            rule_id="HARDCODED_CLIENT_SECRET",
                                            severity="HIGH",
                                            description=f"Client '{client_name}' server '{s_name}' contains static secret in env '{k}'",
                                            file=str(p),
                                            line=1,
                                            match=f"{k}={self.redact(v_str, 6)}",
                                            cve_ref="CWE-798"
                                        )
                                        findings.append(f)
                                        self._findings.append(f)
                    except Exception:
                        pass
                elif p.is_dir():
                    # Scan directory (e.g. Antigravity MCP directory)
                    findings.extend(self.scan_directory(p))
        return findings

    # ── Category E: Reporting, Scoring & Attestation ─────────────────
    @staticmethod
    def shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        from collections import Counter
        import math
        freq = Counter(s)
        length = len(s)
        return -sum((c / length) * math.log2(c / length) for c in freq.values())

    def calculate_score(self) -> (int, str):
        """
        Calculates Security Score (0-100) and Letter Grade (A, B, C, F).
        """
        score = 100
        for f in self._findings:
            if f.severity == "CRITICAL":
                score -= 35
            elif f.severity == "HIGH":
                score -= 15
            elif f.severity == "MEDIUM":
                score -= 5
            elif f.severity == "LOW":
                score -= 2

        for alert in self._framework_alerts:
            sev = str(alert.get("severity", "")).upper()
            if "CRITICAL" in sev:
                score -= 25
            elif "HIGH" in sev:
                score -= 10
            elif "MEDIUM" in sev:
                score -= 5

        score = max(0, min(100, score))
        if score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B"
        elif score >= 65:
            grade = "C"
        else:
            grade = "F"
        return score, grade

    def generate_report(self) -> ScanReport:
        findings_data = [{"rule": f.rule_id, "severity": f.severity, "file": f.file, "line": f.line} for f in self._findings]
        payload = json.dumps(findings_data, sort_keys=True)
        attestation = hashlib.sha256(payload.encode()).hexdigest()
        score, grade = self.calculate_score()
        return ScanReport(
            scan_id=f"mcp_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            files_scanned=self._files_scanned,
            findings=self._findings,
            clean=len(self._findings) == 0 and len(self._framework_alerts) == 0,
            attestation_hash=attestation,
            framework_alerts=self._framework_alerts,
            score=score,
            grade=grade,
            tool_schemas_scanned=self._tool_schemas_scanned,
            client_configs_scanned=self._client_configs_scanned
        )

    def generate_attestation(self) -> Dict[str, Any]:
        report = self.generate_report()
        severity_breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self._findings:
            severity_breakdown[f.severity] = severity_breakdown.get(f.severity, 0) + 1
        return {
            "scan_id": report.scan_id,
            "timestamp": report.timestamp,
            "verdict": "CLEAN" if report.clean else "VULNERABLE",
            "score": report.score,
            "grade": report.grade,
            "total_findings": len(self._findings),
            "severity_breakdown": severity_breakdown,
            "framework_alerts": len(self._framework_alerts),
            "tool_schemas_scanned": report.tool_schemas_scanned,
            "client_configs_scanned": report.client_configs_scanned,
            "attestation_hash": report.attestation_hash
        }

    def generate_markdown_scorecard(self) -> str:
        """
        Generates an Institutional Markdown Security Audit Scorecard.
        """
        report = self.generate_report()
        status_badge = "🛡️ **HARDENED (PASS)**" if report.score >= 80 else "⚠️ **VULNERABLE (FAIL)**"
        
        md = []
        md.append(f"# Trishula MCP Shield v2.0 — Institutional Security Scorecard\n")
        md.append(f"**Audit Status:** {status_badge}  ")
        md.append(f"**Security Score:** `{report.score}/100` (Grade **{report.grade}**)  ")
        md.append(f"**Scan ID:** `{report.scan_id}`  ")
        md.append(f"**Attestation SHA-256:** `{report.attestation_hash}`  ")
        md.append(f"**Timestamp:** `{report.timestamp}`\n")
        md.append("---\n")

        md.append("## 📊 Scan Telemetry Summary\n")
        md.append("| Metric | Count | Standard |")
        md.append("| :--- | :--- | :--- |")
        md.append(f"| **Files Scanned** | {report.files_scanned} | Pure Stdlib Traversal |")
        md.append(f"| **Tool Schemas Audited** | {report.tool_schemas_scanned} | MCP JSON-RPC 2.0 Standard |")
        md.append(f"| **Client Configs Verified** | {report.client_configs_scanned} | Claude / Antigravity / Cursor |")
        md.append(f"| **Total Vulnerability Findings** | {len(report.findings)} | SQA_v5_ASCENDED Deterministic |")
        md.append(f"| **Compromised Framework Alerts** | {len(report.framework_alerts)} | Supply Chain Advisory DB |")
        md.append(f"| **Audit Verdict** | **{report.grade} ({'PASS' if report.clean else 'ACTION REQUIRED'})** | MC/DC Zero-Tolerance |\n")

        if report.findings:
            md.append("## 🚨 Security Findings Detail\n")
            md.append("| Severity | Rule ID | Reference | File / Target | Details |")
            md.append("| :---: | :--- | :---: | :--- | :--- |")
            for f in report.findings:
                md.append(f"| `{f.severity}` | `{f.rule_id}` | `{f.cve_ref}` | `{os.path.basename(f.file)}` (Line {f.line}) | {f.description} (`{f.match}`) |")
            md.append("\n")

        if report.framework_alerts:
            md.append("## ⚠️ Upstream Supply Chain Advisories\n")
            md.append("| Target | Status / Warning |")
            md.append("| :--- | :--- |")
            for alert in report.framework_alerts:
                pkg = alert.get("framework") or alert.get("package")
                sev = alert.get("severity")
                md.append(f"| `{pkg}` | {sev} |")
            md.append("\n")

        md.append("## 🔒 Cryptographic Attestation Receipt\n")
        md.append("```json")
        md.append(json.dumps(self.generate_attestation(), indent=2))
        md.append("```\n")
        md.append("> *Certified by Trishula MCP Shield — Sovereign Security for Autonomous Agents.*")
        return "\n".join(md)

# ── CLI Interface ──────────────────────────────────────────────────
def main():
    import argparse
    parser = argparse.ArgumentParser(description="Trishula MCP Shield v2.0 — Protocol Security Scanner")
    parser.add_argument("path", nargs="?", default=".", help="Directory or file to scan (default: current directory)")
    parser.add_argument("--scan-clients", action="store_true", help="Auto-discover and audit installed MCP client configurations")
    parser.add_argument("--tools-json", help="Path to JSON file containing MCP tools/list output")
    parser.add_argument("--markdown", action="store_true", help="Output full institutional Markdown scorecard")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON attestation")
    args = parser.parse_args()

    shield = MCPShield()
    target_path = Path(args.path)

    if args.scan_clients:
        shield.discover_and_scan_client_configs()

    if args.tools_json:
        tools_path = Path(args.tools_json)
        if tools_path.exists():
            try:
                tools_data = json.loads(tools_path.read_text(encoding="utf-8"))
                shield.scan_tools_list(tools_data, source_label=str(tools_path))
            except Exception as e:
                print(f"Error reading tools JSON: {e}", file=sys.stderr)

    if target_path.exists() and not (args.scan_clients and args.path == "."):
        if target_path.is_file():
            shield.scan_file(target_path)
        else:
            shield.scan_directory(target_path)

    if args.markdown:
        print(shield.generate_markdown_scorecard())
    elif args.json:
        print(json.dumps(shield.generate_attestation(), indent=2))
    else:
        scorecard = shield.generate_markdown_scorecard()
        print(scorecard)

    report = shield.generate_report()
    sys.exit(0 if report.clean else 1)

if __name__ == "__main__":
    main()
