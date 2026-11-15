"""Find the Supabase project, public key, tables, RPCs and buckets a deployed site uses.

Reads only the site's own HTML and same-origin JavaScript. It never sends a
request to the Supabase project itself.
"""
import re
import urllib.parse

from . import http
from .jwtutil import decode_unverified

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
NEWKEY_RE = re.compile(r"sb_(publishable|secret)_[A-Za-z0-9_-]{10,}")
SUPA_URL_RE = re.compile(r"https://[a-z0-9-]+\.supabase\.(?:co|in|net)\b")
CREATE_CLIENT_RE = re.compile(r"createClient\(\s*[\"'`](https?://[^\"'`\s]+)[\"'`]")
STORAGE_FROM_RE = re.compile(r"storage\s*\.\s*from\(\s*[\"'`]([A-Za-z0-9_.-]+)[\"'`]")
FROM_RE = re.compile(r"\.from\(\s*[\"'`]([A-Za-z_][A-Za-z0-9_]*)[\"'`]\s*\)")
SCHEMA_FROM_RE = re.compile(r"\.schema\(\s*[\"'`]([A-Za-z_][A-Za-z0-9_]*)[\"'`]\s*\)")
RPC_RE = re.compile(r"\.rpc\(\s*[\"'`]([A-Za-z_][A-Za-z0-9_]*)[\"'`]")
SCRIPT_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)
PRELOAD_RE = re.compile(r"<link[^>]+href=[\"']([^\"']+\.m?js)[\"']", re.I)
CHUNK_RE = re.compile(r"[\"'`]((?:\.{0,2}/)?(?:[A-Za-z0-9_./-]*/)?[A-Za-z0-9_.-]+\.m?js)[\"'`]")

# Common JS identifiers that show up as .from("x") but are not tables.
NOT_TABLES = {"Array", "Buffer", "Uint8Array", "default"}


class Discovery:
    def __init__(self):
        self.site = None
        self.files = []
        self.supabase_urls = set()
        self.anon_keys = set()
        self.service_keys = set()
        self.tables = set()
        self.rpcs = set()
        self.buckets = set()

    @property
    def supabase_url(self):
        urls = sorted(self.supabase_urls)
        return urls[0] if urls else None

    @property
    def anon_key(self):
        keys = sorted(self.anon_keys)
        return keys[0] if keys else None

    def to_dict(self):
        return {
            "site": self.site,
            "files_scanned": self.files,
            "supabase_url": self.supabase_url,
            "supabase_urls": sorted(self.supabase_urls),
            "anon_key_found": bool(self.anon_keys),
            "service_key_in_bundle": bool(self.service_keys),
            "tables": sorted(self.tables),
            "rpcs": sorted(self.rpcs),
            "buckets": sorted(self.buckets),
        }


def scan_text(text, d=None):
    """Extract Supabase details from one HTML/JS text into a Discovery."""
    d = d or Discovery()
    for m in SUPA_URL_RE.finditer(text):
        d.supabase_urls.add(m.group(0))
    for m in CREATE_CLIENT_RE.finditer(text):
        d.supabase_urls.add(m.group(1).rstrip("/"))
    for m in JWT_RE.finditer(text):
        payload = decode_unverified(m.group(0)) or {}
        role = payload.get("role")
        if role == "anon":
            d.anon_keys.add(m.group(0))
        elif role == "service_role":
            d.service_keys.add(m.group(0))
    for m in NEWKEY_RE.finditer(text):
        (d.anon_keys if m.group(1) == "publishable" else d.service_keys).add(m.group(0))
    buckets = {m.group(1) for m in STORAGE_FROM_RE.finditer(text)}
    d.buckets |= buckets
    # Remove storage.from(...) occurrences before looking for tables.
    stripped = STORAGE_FROM_RE.sub("", text)
    for m in FROM_RE.finditer(stripped):
        name = m.group(1)
        if name not in NOT_TABLES:
            d.tables.add(name)
    for m in RPC_RE.finditer(stripped):
        d.rpcs.add(m.group(1))
    return d


def _same_origin(a, b):
    pa, pb = urllib.parse.urlsplit(a), urllib.parse.urlsplit(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)


def discover(site, max_files=40, fetch=None):
    """Fetch a site and its same-origin scripts and extract Supabase usage."""
    fetch = fetch or (lambda u: http.request("GET", u, headers={"Accept": "*/*"}))
    d = Discovery()
    d.site = site
    r = fetch(site)
    if not r.ok:
        raise RuntimeError(f"GET {site} returned HTTP {r.status}")
    html = r.text
    scan_text(html, d)
    queue = []
    for rx in (SCRIPT_RE, PRELOAD_RE):
        for m in rx.finditer(html):
            queue.append(urllib.parse.urljoin(site, m.group(1)))
    seen = set()
    while queue and len(d.files) < max_files:
        u = queue.pop(0)
        if u in seen or not _same_origin(u, site):
            continue
        seen.add(u)
        r = fetch(u)
        if not r.ok:
            continue
        d.files.append(u)
        js = r.text
        scan_text(js, d)
        for m in CHUNK_RE.finditer(js):
            ref = m.group(1)
            if ref.startswith(("http:", "https:")) or "node_modules" in ref:
                continue
            # Vite chunk refs are relative to the importing file, or to the site root.
            for cand in (urllib.parse.urljoin(u, ref), urllib.parse.urljoin(site, ref)):
                if cand not in seen and _same_origin(cand, site):
                    queue.append(cand)
    return d
