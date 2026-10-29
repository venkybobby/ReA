"""Safe URL intake: scheme/IP checks, size cap, content sniffing."""
import hashlib
import ipaddress
import os
import socket
import urllib.parse
import urllib.request

MAX_BYTES = 200 * 1024 * 1024
MAGIC = {
    b"\x7fELF": "elf",
    b"MZ": "pe",
    b"\x00asm": "wasm",
    b"\xca\xfe\xba\xbe": "macho-fat",
    b"\xfe\xed\xfa\xce": "macho",
    b"\xfe\xed\xfa\xcf": "macho",
    b"\xcf\xfa\xed\xfe": "macho",
    b"\xce\xfa\xed\xfe": "macho",
    b"PK\x03\x04": "zip",
}


class FetchError(Exception):
    pass


def check_url(url, allow_private=False):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise FetchError(f"unsupported scheme: {parts.scheme!r}")
    if not parts.hostname:
        raise FetchError("URL has no host")
    if allow_private:
        return parts
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or 443)
    except socket.gaierror as e:
        raise FetchError(f"cannot resolve {parts.hostname}: {e}")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise FetchError(f"{parts.hostname} resolves to non-public address {ip} (use --allow-private)")
    return parts


def sniff(data, content_type=""):
    for magic, kind in MAGIC.items():
        if data.startswith(magic):
            return kind
    head = data[:2048].lstrip().lower()
    if head.startswith((b"<!doctype html", b"<html")) or b"<script" in head or "html" in content_type:
        return "html"
    if "javascript" in content_type or "json" in content_type:
        return "text"
    return "text" if b"\x00" not in data[:4096] else "unknown-binary"


def fetch(url, allow_private=False, max_bytes=MAX_BYTES, timeout=30):
    check_url(url, allow_private)
    req = urllib.request.Request(url, headers={"User-Agent": "rea-toolkit/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        final = r.geturl()
        check_url(final, allow_private)  # re-check after redirects
        ctype = r.headers.get("Content-Type", "")
        data = r.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise FetchError(f"response exceeds {max_bytes} bytes")
    return {"url": final, "content_type": ctype, "data": data, "kind": sniff(data, ctype),
            "sha256": hashlib.sha256(data).hexdigest()}


def save(result, workdir):
    os.makedirs(workdir, exist_ok=True)
    name = os.path.basename(urllib.parse.urlsplit(result["url"]).path) or "download"
    name = "".join(c for c in name if c.isalnum() or c in "._-") or "download"
    path = os.path.join(workdir, f"{result['sha256'][:12]}_{name}")
    with open(path, "wb") as f:
        f.write(result["data"])
    os.chmod(path, 0o600)  # never executable
    return path
