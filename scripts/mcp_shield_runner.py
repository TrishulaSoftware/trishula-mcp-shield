#!/usr/bin/env python3
"""
Trishula MCP Shield — Standalone Runner & Agent Invocation Bridge
Executes MCP Shield security sweeps, tool schema validation, or client config audits.
Outputs formatted Markdown scorecards and JSON attestations.
"""
import sys, os, json
from pathlib import Path

# Ensure root package is in import path
sys.path.insert(0, str(Path(__file__).parent.parent))
from mcp_shield import MCPShield

def run_audit(target_path=".", scan_clients=True, tools_json=None, as_json=False):
    shield = MCPShield()
    
    if scan_clients:
        shield.discover_and_scan_client_configs()
        
    if tools_json and os.path.exists(tools_json):
        try:
            with open(tools_json, "r", encoding="utf-8") as f:
                data = json.load(f)
            shield.scan_tools_list(data, source_label=str(tools_json))
        except Exception as e:
            sys.stderr.write(f"[!] Error scanning tools JSON: {e}\n")

    p = Path(target_path)
    if p.exists():
        if p.is_file():
            shield.scan_file(p)
        elif p.is_dir():
            shield.scan_directory(p)
            
    if as_json:
        return json.dumps(shield.generate_attestation(), indent=2)
    else:
        return shield.generate_markdown_scorecard()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Trishula MCP Shield Runner")
    parser.add_argument("target", nargs="?", default=".", help="Target path to audit")
    parser.add_argument("--no-clients", action="store_true", help="Skip host client autodiscovery")
    parser.add_argument("--tools", help="Audit MCP tools/list JSON file")
    parser.add_argument("--json", action="store_true", help="Output JSON attestation receipt")
    args = parser.parse_args()

    output = run_audit(
        target_path=args.target,
        scan_clients=not args.no_clients,
        tools_json=args.tools,
        as_json=args.json
    )
    print(output)
