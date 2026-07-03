"""Local IP blocklists — free, commercial-use OK, no API key, no per-request quota.

Downloads a few high-signal open blocklists once per day into a cache dir and
checks IPs against them locally. This replaces per-request reputation APIs
(like AbuseIPDB) whose free tiers forbid commercial use.

Sources:
  - FireHOL level1  : aggregated "safe to block" set (includes Spamhaus DROP,
                      DShield, etc.), CC-BY-SA — commercial use permitted.
  - Tor exit nodes  : official Tor exit list.
"""

from __future__ import annotations

import csv
import ipaddress
import os
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from ..common import USER_AGENT
from ..config import cache_dir_override

SOURCES: dict[str, str] = {
    "firehol_level1":
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "tor_exit":
        "https://check.torproject.org/torbulkexitlist",
    "spamhaus_drop":
        "https://www.spamhaus.org/drop/drop.txt",
    "blocklist_de":
        "https://lists.blocklist.de/lists/all.txt",
}

# Domain-based phishing blocklists (MIT-licensed, commercial-use OK, no key).
DOMAIN_SOURCES: dict[str, str] = {
    "phishing_db":
        "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
}

# URLhaus recent malicious-URL feed (CSV, no auth key required for downloads).
URLHAUS_FEED = "https://urlhaus.abuse.ch/downloads/csv_recent/"

TTL_SECONDS = 24 * 3600
DL_TIMEOUT = 40.0


def _cache_dir() -> Path:
    base = cache_dir_override() or os.path.join(
        os.path.expanduser("~"), ".cache", "jobverify-mcp")
    p = Path(base)
    p.mkdir(parents=True, exist_ok=True)
    return p


# In-memory parsed cache: {source: {"hosts": set[str], "nets": list[ip_network],
#                                    "mtime": float}}
_PARSED: dict[str, dict[str, Any]] = {}


def _is_stale(path: Path) -> bool:
    return (not path.exists()) or (time.time() - path.stat().st_mtime > TTL_SECONDS)


async def _download(client: httpx.AsyncClient, url: str, path: Path) -> bool:
    try:
        resp = await client.get(url, headers={"User-Agent": USER_AGENT},
                                timeout=DL_TIMEOUT)
        resp.raise_for_status()
        path.write_text(resp.text)
        return True
    except Exception:
        return False


async def _ensure(sources: dict[str, str]) -> dict[str, bool]:
    """Download any missing/stale lists in `sources`. Returns {name: available}."""
    cache = _cache_dir()
    status: dict[str, bool] = {}
    async with httpx.AsyncClient(follow_redirects=True) as client:
        for name, url in sources.items():
            path = cache / f"{name}.txt"
            if _is_stale(path):
                ok = await _download(client, url, path)
                # If download failed but a stale copy exists, still use it.
                status[name] = ok or path.exists()
            else:
                status[name] = True
    return status


async def ensure_fresh() -> dict[str, bool]:
    """Download any missing/stale IP blocklists. Returns {source: available}."""
    return await _ensure(SOURCES)


async def ensure_fresh_domains() -> dict[str, bool]:
    """Download any missing/stale domain blocklists. Returns {source: available}."""
    return await _ensure(DOMAIN_SOURCES)


def _parse_file(path: Path) -> dict[str, Any]:
    hosts: set[str] = set()
    nets: list[ipaddress._BaseNetwork] = []
    try:
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            entry = line.split()[0].split(";")[0].strip()
            if not entry:
                continue
            try:
                if "/" in entry:
                    nets.append(ipaddress.ip_network(entry, strict=False))
                else:
                    hosts.add(entry)
            except ValueError:
                continue
    except OSError:
        pass
    return {"hosts": hosts, "nets": nets, "mtime": path.stat().st_mtime
            if path.exists() else 0.0}


def _load(name: str) -> dict[str, Any]:
    """Load & cache a parsed blocklist, reloading if the file changed."""
    path = _cache_dir() / f"{name}.txt"
    cached = _PARSED.get(name)
    file_mtime = path.stat().st_mtime if path.exists() else 0.0
    if cached is None or cached.get("mtime") != file_mtime:
        _PARSED[name] = _parse_file(path)
    return _PARSED[name]


def check_ip_local(ip: str) -> list[str]:
    """Return the list of blocklist sources that contain `ip` (empty if clean).

    Assumes ensure_fresh() has been awaited beforehand so files exist.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return []
    hits: list[str] = []
    for name in SOURCES:
        data = _load(name)
        if ip in data["hosts"]:
            hits.append(name)
            continue
        for net in data["nets"]:
            if addr.version == net.version and addr in net:
                hits.append(name)
                break
    return hits


# --------------------------------------------------------------------------- #
# Domain blocklists
# --------------------------------------------------------------------------- #
_DOMAIN_PARSED: dict[str, dict[str, Any]] = {}


def _parse_domain_file(path: Path) -> dict[str, Any]:
    domains: set[str] = set()
    try:
        for line in path.read_text().splitlines():
            line = line.strip().lower()
            if not line or line.startswith("#"):
                continue
            # hosts-file format ("0.0.0.0 domain") or bare domain
            parts = line.split()
            domain = parts[-1] if parts else ""
            if domain and "." in domain:
                domains.add(domain.rstrip("."))
    except OSError:
        pass
    return {"domains": domains,
            "mtime": path.stat().st_mtime if path.exists() else 0.0}


def _load_domains(name: str) -> dict[str, Any]:
    path = _cache_dir() / f"{name}.txt"
    cached = _DOMAIN_PARSED.get(name)
    file_mtime = path.stat().st_mtime if path.exists() else 0.0
    if cached is None or cached.get("mtime") != file_mtime:
        _DOMAIN_PARSED[name] = _parse_domain_file(path)
    return _DOMAIN_PARSED[name]


def check_domain_local(domain: str) -> list[str]:
    """Return domain blocklist sources that list `domain` (or a parent domain).

    Checks the full host and each parent suffix, so 'login.acme.evil.tld' matches
    a listing of 'evil.tld'. Assumes ensure_fresh_domains() was awaited first.
    """
    domain = domain.strip().lower().rstrip(".")
    if not domain:
        return []
    labels = domain.split(".")
    # candidate suffixes: full host down to the last two labels
    candidates = {".".join(labels[i:]) for i in range(len(labels) - 1)}
    candidates.add(domain)

    hits: list[str] = []
    for name in DOMAIN_SOURCES:
        data = _load_domains(name)
        if candidates & data["domains"]:
            hits.append(name)
    return hits


# --------------------------------------------------------------------------- #
# URLhaus recent malicious-URL feed (host-level matching)
# --------------------------------------------------------------------------- #
_URLHAUS_PARSED: dict[str, Any] = {}


async def ensure_fresh_urlhaus() -> bool:
    """Download the URLhaus recent feed if stale. Returns True if available."""
    path = _cache_dir() / "urlhaus_recent.csv"
    if _is_stale(path):
        async with httpx.AsyncClient(follow_redirects=True) as client:
            try:
                resp = await client.get(URLHAUS_FEED,
                                        headers={"User-Agent": USER_AGENT},
                                        timeout=DL_TIMEOUT)
                resp.raise_for_status()
                path.write_text(resp.text)
            except Exception:
                pass
    return path.exists()


def _load_urlhaus() -> set[str]:
    """Parse malicious hostnames (domains and IPs) from the URLhaus CSV."""
    path = _cache_dir() / "urlhaus_recent.csv"
    file_mtime = path.stat().st_mtime if path.exists() else 0.0
    if _URLHAUS_PARSED.get("mtime") == file_mtime:
        return _URLHAUS_PARSED["hosts"]

    hosts: set[str] = set()
    if path.exists():
        # CSV columns: id, dateadded, url, url_status, last_online, threat, ...
        lines = (ln for ln in path.read_text().splitlines() if not ln.startswith("#"))
        for row in csv.reader(lines):
            if len(row) < 3:
                continue
            host = (urlparse(row[2]).hostname or "").lower().strip(".")
            if host:
                hosts.add(host)
    _URLHAUS_PARSED["hosts"] = hosts
    _URLHAUS_PARSED["mtime"] = file_mtime
    return hosts


def check_url_host(host: str) -> bool:
    """True if `host` (or a parent domain) appears in the URLhaus recent feed."""
    host = host.strip().lower().rstrip(".")
    if not host:
        return False
    hosts = _load_urlhaus()
    if host in hosts:
        return True
    labels = host.split(".")
    return any(".".join(labels[i:]) in hosts for i in range(1, len(labels) - 1)) \
        if len(labels) > 2 else False
