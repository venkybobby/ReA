"""Static analysis of a web page and its scripts (no execution)."""
import re
import urllib.parse

from .fetch import FetchError, fetch

SCRIPT_SRC = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.I)
URL_RE = re.compile(r"""https?://[^\s"'<>\\)]+""")
PATH_RE = re.compile(r"""["'](/(?:api|v\d|graphql|rest|auth|oauth|admin)[^"'\s]*)["']""", re.I)
SOURCEMAP = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")
SECRETS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
}


def scan_text(text):
    return {
        "urls": sorted(set(URL_RE.findall(text))),
        "api_paths": sorted(set(PATH_RE.findall(text))),
        "source_maps": sorted(set(SOURCEMAP.findall(text))),
        "possible_secrets": sorted({k for k, rx in SECRETS.items() if rx.search(text)}),
    }


def analyze_web(page, allow_private=False, max_scripts=20):
    html = page["data"].decode("utf-8", "replace")
    scripts = []
    for src in SCRIPT_SRC.findall(html)[:max_scripts]:
        scripts.append(urllib.parse.urljoin(page["url"], src))
    combined = html
    fetched, failed = [], []
    for s in scripts:
        try:
            r = fetch(s, allow_private=allow_private, max_bytes=10 * 1024 * 1024)
            combined += "\n" + r["data"].decode("utf-8", "replace")
            fetched.append(s)
        except (FetchError, OSError) as e:
            failed.append({"url": s, "error": str(e)})
    report = scan_text(combined)
    report.update({"page": page["url"], "sha256": page["sha256"], "scripts_fetched": fetched,
                   "scripts_failed": failed})
    return report
