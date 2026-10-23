"""The 10-tool allowlist (session, procedures, strings, xrefs).

Upstream tool names differ between REA builds, so each entry is a regex that is
matched against the upstream tool name. A custom allowlist can be loaded from
JSON: {"groups": {"session": ["regex", ...], ...}}.
"""
import json
import re

DEFAULT_GROUPS = {
    "session": [r"open[_-]?binary", r"close[_-]?binary", r"binary[_-]?session"],
    "procedures": [r"list[_-]?procedures?", r"search[_-]?procedures?", r"decompile[_-]?procedure"],
    "strings": [r"list[_-]?strings?", r"search[_-]?strings?"],
    "xrefs": [r"cross[_-]?references?|xrefs?", r"procedure[_-]?references?"],
}


class Allowlist:
    def __init__(self, groups=None):
        self.groups = groups or DEFAULT_GROUPS
        self._patterns = [
            (g, re.compile(p, re.I)) for g, pats in self.groups.items() for p in pats
        ]

    @classmethod
    def load(cls, path=None):
        if not path:
            return cls()
        with open(path, encoding="utf-8") as f:
            return cls(json.load(f)["groups"])

    def group_of(self, tool_name):
        for group, pat in self._patterns:
            if pat.search(tool_name):
                return group
        return None

    def allows(self, tool_name):
        return self.group_of(tool_name) is not None

    def filter_tools(self, tools):
        return [t for t in tools if self.allows(t.get("name", ""))]


def estimate_tokens(tools):
    """Rough token estimate of a tool list (~4 chars/token)."""
    return len(json.dumps(tools, separators=(",", ":"))) // 4
