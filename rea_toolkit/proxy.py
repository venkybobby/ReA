"""Stdio MCP proxy that exposes only allowlisted tools of an upstream server.

Client <-> proxy <-> upstream. `tools/list` responses are filtered and
`tools/call` for a non-allowlisted tool is rejected locally. MCP stdio framing
is one JSON message per line.
"""
import json
import subprocess
import sys
import threading

from .allowlist import Allowlist, estimate_tokens


def run_proxy(cmd, allowlist, stdin=None, stdout=None, log=None):
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    log = log or sys.stderr
    up = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
    list_ids = set()
    lock = threading.Lock()

    def emit(msg):
        with lock:
            stdout.write(json.dumps(msg) + "\n")
            stdout.flush()

    def pump_upstream():
        for line in up.stdout:
            try:
                msg = json.loads(line)
            except ValueError:
                emit_raw(line)
                continue
            if msg.get("id") in list_ids and "result" in msg and "tools" in msg["result"]:
                list_ids.discard(msg["id"])
                before = estimate_tokens(msg["result"]["tools"])
                msg["result"]["tools"] = allowlist.filter_tools(msg["result"]["tools"])
                after = estimate_tokens(msg["result"]["tools"])
                print(f"[rea-toolkit] tools/list ~{before} -> ~{after} tokens", file=log)
            emit(msg)

    def emit_raw(line):
        with lock:
            stdout.write(line)
            stdout.flush()

    t = threading.Thread(target=pump_upstream, daemon=True)
    t.start()
    for line in stdin:
        try:
            msg = json.loads(line)
        except ValueError:
            up.stdin.write(line)
            up.stdin.flush()
            continue
        method = msg.get("method")
        if method == "tools/list" and "id" in msg:
            list_ids.add(msg["id"])
        elif method == "tools/call":
            name = (msg.get("params") or {}).get("name", "")
            if not allowlist.allows(name):
                emit({"jsonrpc": "2.0", "id": msg.get("id"),
                      "error": {"code": -32601, "message": f"tool '{name}' is not in the allowlist"}})
                continue
        up.stdin.write(json.dumps(msg) + "\n")
        up.stdin.flush()
    up.stdin.close()
    up.wait()
    t.join(timeout=2)
    return up.returncode
