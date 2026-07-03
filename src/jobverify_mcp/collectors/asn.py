"""Local IP -> ASN / country / org lookup using the iptoasn.com database.

iptoasn.com publishes a free, **public-domain** IP-to-ASN dataset (no API key,
no quota). We download it once per day, decompress it into the cache dir, and do
a local binary-search lookup. This is the open-source replacement for third-party
IP-info APIs.

Dataset row format (TSV): range_start  range_end  AS_number  country  AS_desc
Unrouted ranges have AS_number 0 and country 'None'.
"""

from __future__ import annotations

import bisect
import gzip
import ipaddress
import sys
from array import array
from pathlib import Path
from typing import Any

import httpx

from ..common import USER_AGENT
from .blocklists import _cache_dir, _is_stale

SOURCES = {
    4: "https://iptoasn.com/data/ip2asn-v4.tsv.gz",
    6: "https://iptoasn.com/data/ip2asn-v6.tsv.gz",
}
DL_TIMEOUT = 60.0

# Parsed, sorted database per IP version. Each is a dict of parallel lists.
_DB: dict[int, dict[str, Any] | None] = {4: None, 6: None}


def _tsv_path(version: int) -> Path:
    return _cache_dir() / f"ip2asn-v{version}.tsv"


async def ensure_fresh() -> dict[int, bool]:
    """Download & decompress any stale iptoasn datasets. Returns {version: available}."""
    status: dict[int, bool] = {}
    async with httpx.AsyncClient(follow_redirects=True) as client:
        for version, url in SOURCES.items():
            path = _tsv_path(version)
            if _is_stale(path):
                try:
                    resp = await client.get(url, headers={"User-Agent": USER_AGENT},
                                            timeout=DL_TIMEOUT)
                    resp.raise_for_status()
                    text = gzip.decompress(resp.content).decode("utf-8", "replace")
                    path.write_text(text)
                    status[version] = True
                except Exception:
                    status[version] = path.exists()  # fall back to cached copy
            else:
                status[version] = True
    return status


def _load(version: int) -> dict[str, Any]:
    """Parse a dataset into sorted parallel lists, cached in memory per file mtime."""
    path = _tsv_path(version)
    file_mtime = path.stat().st_mtime if path.exists() else 0.0
    cached = _DB[version]
    if cached is not None and cached.get("mtime") == file_mtime:
        return cached

    # v4 ints fit in 64-bit -> use compact arrays; v6 (128-bit) needs plain lists.
    if version == 4:
        starts: Any = array("Q")
        ends: Any = array("Q")
        asns: Any = array("Q")
    else:
        starts = []
        ends = []
        asns = []
    ccs: list[str] = []
    descs: list[str] = []
    if path.exists():
        for line in path.read_text().splitlines():
            parts = line.split("\t")
            if len(parts) < 5:
                continue
            try:
                asn = int(parts[2])
                if asn == 0:
                    continue  # unrouted gap; lookup returns None for these anyway
                start = int(ipaddress.ip_address(parts[0]))
                end = int(ipaddress.ip_address(parts[1]))
            except ValueError:
                continue
            starts.append(start)
            ends.append(end)
            asns.append(asn)
            ccs.append(sys.intern(parts[3]))
            descs.append(sys.intern(parts[4]))

    db = {"starts": starts, "ends": ends, "asns": asns, "ccs": ccs,
          "descs": descs, "mtime": file_mtime}
    _DB[version] = db
    return db


def lookup(ip: str) -> dict[str, Any] | None:
    """Return {asn, country, org} for an IP, or None if not found/unrouted.

    Assumes ensure_fresh() was awaited beforehand.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    db = _load(addr.version)
    starts = db["starts"]
    if not starts:
        return None
    key = int(addr)
    idx = bisect.bisect_right(starts, key) - 1
    if idx < 0 or key > db["ends"][idx]:
        return None
    asn = db["asns"][idx]
    if asn == 0:
        return None  # unrouted / bogon
    return {"asn": asn, "country": db["ccs"][idx], "org": db["descs"][idx]}
