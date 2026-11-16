#!/usr/bin/env python3
"""
Trishula MCP Shield v2.5 (SQAV5A) — Model Context Protocol JSON-RPC 2.0 Server
Provides standard MCP tools over STDIO for AI agent orchestration.
Zero external dependencies. Pure Python standard library.
"""
import sys, os, json
from pathlib import Path
from mcp_shield import MCPShield

SERVER_NAME = "trishula-mcp-shield"
SERVER_VERSION = "2.5.0"

TOOLS = [
    {
        "name": "mcp_audit_installed_clients",
        "description": "Auto-discovers and audits all locally configured MCP servers across Claude Desktop, Cursor, and Antigravity for unauthenticated STDIO execution, hardcoded credentials, and configuration flaws.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "format": {
                    "type": "string",
                    "enum": ["markdown", "json", "sarif"],
                    "description": "Output format: 'markdown' scorecard, 'json' attestation, or 'sarif' report.",
                    "default": "markdown"
                }
            }
        }
    },
    {
        "name": "mcp_audit_tool_schema",
        "description": "Audits an MCP tool definition or tools/list payload for prompt injection in descriptions, unconstrained shell/eval primitives, and dangerous data deletion capabilities.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool_definition": {
                    "type": "object",
                    "description": "The JSON object representing a tool definition (name, description, inputSchema) or a full tools/list response dictionary."
                }
            },
            "required": ["tool_definition"]
        }
    },
    {
        "name": "mcp_audit_path",
        "description": "Scans a local repository, file, or directory containing MCP server implementation files for CVE-level vulnerabilities, AST execution sinks, unauthenticated STDIO usage, and compromised dependencies.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_path": {
                    "type": "string",
                    "description": "Absolute or relative path to the directory or file to audit."
                },
                "enable_ast": {
                    "type": "boolean",
                    "description": "Enable SQAV5A Pillar 1 Python AST static verification.",
                    "default": True
                }
            },
            "required": ["target_path"]
        }
    },
    {
        "name": "mcp_intercept_jsonrpc",
        "description": "SQAV5A Zero-RCE Runtime Firewall & Egress Guard: Inspects a live MCP JSON-RPC 2.0 request/response payload against PHP2Shell, Node2Shell, x402 Wallet Drain, JNDI, SSRF, prompt injection, and protected doctrinal boundary paths.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "jsonrpc_payload": {
                    "type": "object",
                    "description": "The JSON-RPC 2.0 frame (method, params, or result) to inspect before execution."
                }
            },
            "required": ["jsonrpc_payload"]
        }
    }
]

def handle_tools_list(request_id):
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "tools": TOOLS
        }
    }

def handle_tools_call(request_id, params):
    tool_name = params.get("name")
    args = params.get("arguments", {})
    shield = MCPShield()

    if tool_name == "mcp_audit_installed_clients":
        shield.discover_and_scan_client_configs()
        fmt = args.get("format", "markdown")
        if fmt == "json":
            res_text = json.dumps(shield.generate_attestation(), indent=2)
        elif fmt == "sarif":
            res_text = json.dumps(shield.generate_sarif_report(), indent=2)
        else:
            res_text = shield.generate_markdown_scorecard()
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [{"type": "text", "text": res_text}]
            }
        }

    elif tool_name == "mcp_audit_tool_schema":
        tool_def = args.get("tool_definition", {})
        if "tools" in tool_def:
            shield.scan_tools_list(tool_def)
        else:
            shield.scan_tool_schema(tool_def)
        res_text = shield.generate_markdown_scorecard()
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [{"type": "text", "text": res_text}]
            }
        }

    elif tool_name == "mcp_audit_path":
        target = Path(args.get("target_path", "."))
        enable_ast = args.get("enable_ast", True)
        if target.is_file():
            shield.scan_file(target)
            if enable_ast and target.suffix.lower() == ".py":
                shield.scan_python_ast(target.read_text(encoding="utf-8", errors="ignore"), str(target))
        else:
            shield.scan_directory(target)
            if enable_ast:
                for root, dirs, files in os.walk(target):
                    dirs[:] = [d for d in dirs if d not in {"node_modules", ".git", "__pycache__", "venv", ".venv"}]
                    for f in files:
                        if f.endswith(".py"):
                            fp = Path(root) / f
                            shield.scan_python_ast(fp.read_text(encoding="utf-8", errors="ignore"), str(fp))
        res_text = shield.generate_markdown_scorecard()
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [{"type": "text", "text": res_text}]
            }
        }

    elif tool_name == "mcp_intercept_jsonrpc":
        payload = args.get("jsonrpc_payload", {})
        verdict = shield.intercept_jsonrpc_message(payload)
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [{"type": "text", "text": json.dumps(verdict, indent=2)}]
            }
        }

    else:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": -32601,
                "message": f"Method '{tool_name}' not found"
            }
        }

def main():
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue

        method = req.get("method")
        req_id = req.get("id")

        if method == "initialize":
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION}
                }
            }
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            resp = handle_tools_list(req_id)
        elif method == "tools/call":
            resp = handle_tools_call(req_id, req.get("params", {}))
        elif method == "ping":
            resp = {"jsonrpc": "2.0", "id": req_id, "result": {}}
        else:
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method '{method}' not implemented"}
            }

        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()

if __name__ == "__main__":
    main()
