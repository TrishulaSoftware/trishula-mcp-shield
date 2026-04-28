"""Trishula MCP Shield — Test Suite (35 tests across 6 categories)"""
import os, sys, json, tempfile, hashlib
from pathlib import Path
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_shield import MCPShield, UNSAFE_PATTERNS, AFFECTED_FRAMEWORKS, Finding

PASSED = 0; FAILED = 0
def test(name, cond):
    global PASSED, FAILED
    if cond: PASSED += 1; print(f"  [PASS] {name}")
    else: FAILED += 1; print(f"  [FAIL] {name}")
def section(t): print(f"\n{'='*60}\n  {t}\n{'='*60}")

# ═══ CATEGORY 1: INITIALIZATION ═══
section("CATEGORY 1: INITIALIZATION")
s = MCPShield()
test("Scanner initializes", s is not None)
test(f"Pattern count: {s.pattern_count}", s.pattern_count == 12)
test("Compiled patterns ready", len(s._compiled) == 12)

# ═══ CATEGORY 2: UNSAFE TRANSPORT DETECTION ═══
section("CATEGORY 2: UNSAFE TRANSPORT DETECTION")
s.reset()
findings = s.scan_content('transport = "stdio"')
test("Detects STDIO transport", len(findings) > 0 and findings[0].rule_id == "STDIO_TRANSPORT_UNAUTH")
test("Severity is CRITICAL", findings[0].severity == "CRITICAL")

s.reset()
findings = s.scan_content('authentication = "none"')
test("Detects disabled auth", len(findings) > 0 and findings[0].rule_id == "MISSING_AUTH")

s.reset()
findings = s.scan_content('auth: false')
test("Detects auth=false", len(findings) > 0)

s.reset()
findings = s.scan_content('cors: "*"')
test("Detects wildcard CORS", len(findings) > 0 and findings[0].rule_id == "WILDCARD_CORS")

s.reset()
findings = s.scan_content('expose_tools = "all"')
test("Detects exposed tools", len(findings) > 0 and findings[0].rule_id == "EXPOSED_TOOLS")

s.reset()
findings = s.scan_content('rate_limit = 0')
test("Detects no rate limit", len(findings) > 0 and findings[0].rule_id == "NO_RATE_LIMIT")

s.reset()
findings = s.scan_content('debug = true')
test("Detects debug mode", len(findings) > 0 and findings[0].rule_id == "DEBUG_MODE")

s.reset()
findings = s.scan_content('result = pickle.loads(data)')
test("Detects unsafe deserialization", len(findings) > 0 and findings[0].rule_id == "UNSAFE_DESERIALIZATION")

s.reset()
findings = s.scan_content('host = "0.0.0.0"')
test("Detects bind all interfaces", len(findings) > 0 and findings[0].rule_id == "BIND_ALL_INTERFACES")

s.reset()
findings = s.scan_content('from langchain.tools import mcp')
test("Detects LangChain MCP", len(findings) > 0 and findings[0].rule_id == "LANGCHAIN_MCP")

s.reset()
findings = s.scan_content('from litellm import completion')
test("Detects LiteLLM import", len(findings) > 0 and findings[0].rule_id == "LITELLM_IMPORT")

# ═══ CATEGORY 3: FALSE POSITIVE SUPPRESSION ═══
section("CATEGORY 3: FALSE POSITIVE SUPPRESSION")
s.reset()
clean_samples = [
    '# transport = "stdio"  -- this is a comment',
    'x = 42',
    'name = "hello world"',
    'transport = "https"',
    'auth = "bearer_token_required"',
]
for sample in clean_samples:
    findings = s.scan_content(sample)
    test(f"No FP: {sample[:45]}...", len(findings) == 0)

# ═══ CATEGORY 4: FRAMEWORK DETECTION ═══
section("CATEGORY 4: FRAMEWORK DETECTION")
s.reset()
alerts = s.check_frameworks("import langchain\nimport litellm\nfrom flowise import agent")
test("Detects langchain", any(a["framework"] == "langchain" for a in alerts))
test("Detects litellm", any(a["framework"] == "litellm" for a in alerts))
test("Detects flowise", any(a["framework"] == "flowise" for a in alerts))
test("Total framework alerts", len(alerts) >= 3)

# Requirements checking
with tempfile.TemporaryDirectory() as tmpdir:
    req = os.path.join(tmpdir, "requirements.txt")
    with open(req, 'w') as f:
        f.write("flask>=3.0\nlitellm==1.0.0\nlangchain>=0.1\n")
    s.reset()
    alerts = s.check_requirements(req)
    test("Requirements: detects litellm", any(a["package"] == "litellm" for a in alerts))
    test("Requirements: detects langchain", any(a["package"] == "langchain" for a in alerts))

# ═══ CATEGORY 5: FILE & DIRECTORY SCANNING ═══
section("CATEGORY 5: FILE & DIRECTORY SCANNING")
with tempfile.TemporaryDirectory() as tmpdir:
    vuln_file = os.path.join(tmpdir, "mcp_config.py")
    with open(vuln_file, 'w') as f:
        f.write('transport = "stdio"\nauthentication = "none"\nhost = "0.0.0.0"\n')
    s.reset()
    findings = s.scan_file(vuln_file)
    test("File scan finds vulnerabilities", len(findings) >= 3)
    test("Finding has line number", findings[0].line >= 1)
    test("Finding is redacted", "****" in findings[0].match)

    clean_file = os.path.join(tmpdir, "safe.py")
    with open(clean_file, 'w') as f:
        f.write('x = 42\nname = "hello"\n')
    s.reset()
    findings = s.scan_file(clean_file)
    test("Clean file has no findings", len(findings) == 0)

    s.reset()
    s.scan_directory(tmpdir)
    test("Directory scan works", s._files_scanned >= 2)

# ═══ CATEGORY 6: REPORTING & ATTESTATION ═══
section("CATEGORY 6: REPORTING & ATTESTATION")
with tempfile.TemporaryDirectory() as tmpdir:
    vuln = os.path.join(tmpdir, "vuln.py")
    with open(vuln, 'w') as f:
        f.write('transport = "stdio"\n')
    s.reset()
    s.scan_file(vuln)
report = s.generate_report()
test("Report has scan ID", report.scan_id.startswith("mcp_"))
test("Report has timestamp", len(report.timestamp) > 0)
test("Report is NOT clean", not report.clean)
test("Report has attestation hash", len(report.attestation_hash) == 64)

s.reset()
s.scan_content("x = 42", "clean.py")
attestation = s.generate_attestation()
test("Clean attestation verdict", attestation["verdict"] == "CLEAN")
test("Attestation has severity breakdown", "CRITICAL" in attestation["severity_breakdown"])

test("Redact short", MCPShield.redact("abc") == "****")
test("Redact long", "****" in MCPShield.redact("transport_stdio_unsafe"))
test("Shannon entropy works", MCPShield.shannon_entropy("abcd") > 0)
test("Empty entropy = 0", MCPShield.shannon_entropy("") == 0.0)

# ═══ VERDICT ═══
print(f"\n{'='*60}")
total = PASSED + FAILED
print(f"  RESULTS: {PASSED}/{total} PASSED, {FAILED}/{total} FAILED")
print(f"  VERDICT: {'SQA_v5_ASCENDED: EXCEEDED' if FAILED == 0 else 'SQA FAIL'}")
print(f"{'='*60}")
if FAILED > 0: sys.exit(1)
