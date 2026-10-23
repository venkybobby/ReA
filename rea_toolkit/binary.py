"""Binary intake: triage plus the MCP config that hands it to REA with the allowlist."""
import json
import re

ASCII = re.compile(rb"[\x20-\x7e]{6,}")


def extract_strings(data, limit=200):
    return [m.decode() for m in ASCII.findall(data)[:limit]]


def triage(result, path):
    return {
        "kind": result["kind"],
        "sha256": result["sha256"],
        "size": len(result["data"]),
        "saved_to": path,
        "sample_strings": extract_strings(result["data"], 40),
    }


def mcp_config(path, rea_cmd):
    """Client config launching REA behind the allowlist proxy."""
    return {"mcpServers": {"rea": {"command": "rea-toolkit",
                                   "args": ["proxy", "--", *rea_cmd]}},
            "suggested_prompt": f"Analyze the binary at {path}: open it, find the key "
                                "procedures and strings, decompile them, and cite evidence "
                                "from tool output. Close the binary when done."}


def dumps(cfg):
    return json.dumps(cfg, indent=2)
