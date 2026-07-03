"""Check a crypto address against open scam-address datasets (no key).

Job/recruiter scams increasingly ask for an up-front crypto payment or use the
victim as a money mule. `extract_entities` already pulls crypto addresses out of
a message; this tool checks them against community scam databases, downloaded
once per day and matched locally (like the other blocklists).

Coverage note: sources are Web3/EVM-focused (ETH-family incl. USDT-ERC20, which
dominate modern scams). BTC coverage is partial.
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from ..common import RiskLevel, USER_AGENT
from .blocklists import _cache_dir, _is_stale

SOURCES = {
    # ScamSniffer: JSON array of lowercase EVM addresses.
    "scamsniffer": "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json",
    # MyEtherWallet ethereum-lists darklist: JSON array of {address, comment}.
    "mew_darklist": "https://raw.githubusercontent.com/MyEtherWallet/ethereum-lists/master/src/addresses/addresses-darklist.json",
}
DL_TIMEOUT = 40.0

_ETH_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
_BTC_RE = re.compile(r"^(bc1[ac-hj-np-z0-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,39})$")

_PARSED: dict[str, Any] = {}


async def ensure_fresh() -> dict[str, bool]:
    """Download stale scam-address datasets. Returns {source: available}."""
    cache = _cache_dir()
    status: dict[str, bool] = {}
    async with httpx.AsyncClient(follow_redirects=True) as client:
        for name, url in SOURCES.items():
            path = cache / f"crypto_{name}.json"
            if _is_stale(path):
                try:
                    resp = await client.get(url, headers={"User-Agent": USER_AGENT},
                                            timeout=DL_TIMEOUT)
                    resp.raise_for_status()
                    path.write_text(resp.text)
                    status[name] = True
                except Exception:
                    status[name] = path.exists()
            else:
                status[name] = True
    return status


def _load() -> set[str]:
    """Parse all datasets into one lowercased address set (cached per mtimes)."""
    cache = _cache_dir()
    paths = {n: cache / f"crypto_{n}.json" for n in SOURCES}
    mtimes = tuple(p.stat().st_mtime if p.exists() else 0.0 for p in paths.values())
    if _PARSED.get("mtimes") == mtimes:
        return _PARSED["addresses"]

    addresses: set[str] = set()
    for path in paths.values():
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        items = data.values() if isinstance(data, dict) else data
        for item in items:
            addr = item.get("address") if isinstance(item, dict) else item
            if isinstance(addr, str) and addr:
                addresses.add(addr.strip().lower())
    _PARSED["addresses"] = addresses
    _PARSED["mtimes"] = mtimes
    return addresses


async def run(address: str) -> dict[str, Any]:
    """Check whether a crypto address appears in open scam databases."""
    address = address.strip()
    kind = "ETH/EVM" if _ETH_RE.match(address) else (
        "BTC" if _BTC_RE.match(address) else None)
    if kind is None:
        return {
            "check": "crypto_address",
            "risk": RiskLevel.YELLOW,
            "summary": f"'{address}' is not a recognized BTC or EVM address format.",
            "findings": {"input": address},
        }

    status = await ensure_fresh()
    listed = address.lower() in _load()

    notes: list[str] = []
    unavailable = [n for n, ok in status.items() if not ok]
    if unavailable:
        notes.append(f"Dataset(s) not refreshed: {', '.join(unavailable)} "
                     "(using cache if present).")
    if kind == "BTC":
        notes.append("BTC coverage is partial; a clean result is weaker for BTC.")

    if listed:
        risk = RiskLevel.RED
        summary = "Address is in an open scam/abuse database — strong fraud signal."
    else:
        risk = RiskLevel.GREEN
        summary = ("Not found in scam databases. Note: any request to pay/receive "
                   "crypto for a job is itself a major red flag, listed or not.")

    return {
        "check": "crypto_address",
        "risk": risk,
        "summary": summary,
        "findings": {"address": address, "type": kind, "in_scam_database": listed},
        "notes": notes,
    }
