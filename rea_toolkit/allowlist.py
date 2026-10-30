"""The 10-tool allowlist (session, procedures, strings, xrefs).

Each entry is a regex that must match the whole upstream tool name. A custom allowlist can be loaded from
JSON: {"groups": {"session": ["regex", ...], ...}}.
"""
import json
import re

# Tool names read from rea-agents 6.8.0 (dist/ contract definitions). Anchored so that
# similarly named tools of other providers do not slip in. Not run against a live server.
DEFAULT_GROUPS = {
    "session": [r"open_binary", r"close_binary", r"binary_session"],
    "procedures": [r"list_procedures", r"search_procedures", r"procedure_pseudo_code"],
    "strings": [r"list_strings", r"search_strings"],
    "xrefs": [r"procedure_references", r"procedure_callers"],
}


class Allowlist:
    def __init__(self, groups=None):
        self.groups = groups or DEFAULT_GROUPS
        self._patterns = [
            (g, re.compile(rf"^(?:{p})$", re.I)) for g, pats in self.groups.items() for p in pats
        ]

    @classmethod
    def load(cls, path=None):
        if not path:
            return cls()
        with open(path, encoding="utf-8") as f:
            return cls(json.load(f)["groups"])

    def group_of(self, tool_name):
        for group, pat in self._patterns:
            if pat.match(tool_name):
                return group
        return None

    def allows(self, tool_name):
        return self.group_of(tool_name) is not None

    def filter_tools(self, tools):
        return [t for t in tools if self.allows(t.get("name", ""))]


def estimate_tokens(tools):
    """Rough token estimate of a tool list (~4 chars/token)."""
    return len(json.dumps(tools, separators=(",", ":"))) // 4
