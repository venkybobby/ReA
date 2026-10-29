import argparse
import json
import os
import shlex
import sys

from . import __version__
from .allowlist import Allowlist
from .binary import mcp_config, triage
from .fetch import FetchError, fetch, save
from .prompts import PROMPTS, render
from .proxy import run_proxy
from .web import analyze_web

BINARY_KINDS = {"elf", "pe", "wasm", "macho", "macho-fat", "unknown-binary"}


def cmd_analyze(a):
    try:
        res = fetch(a.url, allow_private=a.allow_private)
    except (FetchError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if res["kind"] in BINARY_KINDS:
        path = save(res, a.workdir)
        out = {"route": "binary", **triage(res, path),
               "rea": mcp_config(path, shlex.split(a.rea_cmd))}
    elif res["kind"] in ("html", "text"):
        out = {"route": "web", **analyze_web(res, allow_private=a.allow_private)}
    else:
        path = save(res, a.workdir)
        out = {"route": "archive", "saved_to": path, "sha256": res["sha256"],
               "note": "archive saved, not extracted; unpack it manually and analyze members"}
    print(json.dumps(out, indent=2))
    return 0


def cmd_proxy(a):
    cmd = a.upstream[1:] if a.upstream[:1] == ["--"] else a.upstream
    if not cmd:
        print("error: give the upstream REA command after --", file=sys.stderr)
        return 2
    return run_proxy(cmd, Allowlist.load(a.allowlist))


def cmd_prompts(a):
    if not a.name:
        for n, t in PROMPTS.items():
            print(f"{n:11} {t[:70]}...")
        return 0
    if a.name not in PROMPTS:
        print(f"error: unknown prompt {a.name!r}; run 'rea-toolkit prompts'", file=sys.stderr)
        return 2
    vals = dict(kv.split("=", 1) for kv in a.set if "=" in kv)
    print(render(a.name, vals))
    return 0


def cmd_allowlist(a):
    al = Allowlist.load(a.allowlist)
    print(json.dumps(al.groups, indent=2))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="rea-toolkit", description=__doc__)
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    an = sub.add_parser("analyze", help="fetch a URL and route it to binary or web analysis")
    an.add_argument("url")
    an.add_argument("--workdir", default=os.path.join(os.getcwd(), "rea-work"))
    an.add_argument("--rea-cmd", default="npx -y rea-agents@6.8.0 mcp", help="command that starts the REA MCP server (stdio)")
    an.add_argument("--allow-private", action="store_true", help="allow private/loopback hosts")
    an.set_defaults(fn=cmd_analyze)
    pr = sub.add_parser("proxy", help="stdio MCP proxy exposing only allowlisted tools")
    pr.add_argument("--allowlist", help="JSON file overriding the default 10-tool allowlist")
    pr.add_argument("upstream", nargs=argparse.REMAINDER)
    pr.set_defaults(fn=cmd_proxy)
    pm = sub.add_parser("prompts", help="list or print investigation prompts (from REA-Prompts, MIT)")
    pm.add_argument("name", nargs="?")
    pm.add_argument("--set", action="append", default=[], metavar="KEY=VALUE",
                    help="fill <KEY> placeholders, e.g. --set TARGET=./app --set FEATURE=export")
    pm.set_defaults(fn=cmd_prompts)
    al = sub.add_parser("allowlist", help="print the active allowlist")
    al.add_argument("--allowlist")
    al.set_defaults(fn=cmd_allowlist)
    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
