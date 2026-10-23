import io
import json
import sys
import textwrap

import pytest

from rea_toolkit.allowlist import Allowlist
from rea_toolkit.fetch import FetchError, check_url, sniff
from rea_toolkit.proxy import run_proxy
from rea_toolkit.web import scan_text

TOOLS = [{"name": n, "description": "x" * 100} for n in [
    "open_binary", "close_binary", "binary_session", "list_procedures", "search_procedures",
    "decompile_procedure", "list_strings", "search_strings", "cross_references",
    "procedure_references", "patch_bytes", "rename_symbol", "run_script"]]


def test_allowlist_has_exactly_ten():
    kept = Allowlist().filter_tools(TOOLS)
    assert len(kept) == 10
    assert {"patch_bytes", "rename_symbol", "run_script"}.isdisjoint(t["name"] for t in kept)


def test_sniff():
    assert sniff(b"\x7fELF....") == "elf"
    assert sniff(b"<html><body>") == "html"
    assert sniff(b"\x00\x01\x02\x03") == "unknown-binary"


def test_check_url_rejects_bad_targets():
    with pytest.raises(FetchError):
        check_url("file:///etc/passwd")
    with pytest.raises(FetchError):
        check_url("http://127.0.0.1/")


def test_scan_text():
    r = scan_text('fetch("/api/v1/users"); // https://x.example/a AKIAABCDEFGHIJKLMNOP')
    assert "/api/v1/users" in r["api_paths"]
    assert "aws_access_key" in r["possible_secrets"]


FAKE = textwrap.dedent("""
    import sys, json
    tools = %s
    for line in sys.stdin:
        m = json.loads(line)
        if m["method"] == "tools/list":
            print(json.dumps({"jsonrpc":"2.0","id":m["id"],"result":{"tools":tools}}), flush=True)
        else:
            print(json.dumps({"jsonrpc":"2.0","id":m["id"],"result":{"ok":True}}), flush=True)
""") % json.dumps(TOOLS)


def test_proxy_filters_and_blocks(tmp_path):
    script = tmp_path / "fake.py"
    script.write_text(FAKE)
    msgs = [{"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "patch_bytes"}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "list_strings"}}]
    out = io.StringIO()
    run_proxy([sys.executable, str(script)], Allowlist(),
              stdin=io.StringIO("\n".join(map(json.dumps, msgs)) + "\n"), stdout=out, log=io.StringIO())
    by_id = {m["id"]: m for m in map(json.loads, out.getvalue().splitlines())}
    assert len(by_id[1]["result"]["tools"]) == 10
    assert "not in the allowlist" in by_id[2]["error"]["message"]
    assert by_id[3]["result"] == {"ok": True}
