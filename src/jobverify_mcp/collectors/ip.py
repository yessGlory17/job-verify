"""IP reputation — 100% key-free, open-source data only.

  - Local blocklists (FireHOL level1 + Tor exit list), refreshed daily and
    checked locally — see blocklists.py.
  - Local IP->ASN lookup (iptoasn.com public-domain dataset) for org/country and
    a hosting/datacenter heuristic — see asn.py.

No API keys, no per-request quotas, commercial-use OK. An 'IK/recruiter' message
originating from a datacenter/blocklisted IP is a meaningful scam signal.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from ..common import RiskLevel
from . import asn, blocklists

# AS-description keywords that indicate hosting rather than a residential ISP.
HOSTING_HINTS = ("hosting", "cloud", "datacenter", "data center", "server",
                 "vps", "colo", "digitalocean", "amazon", "aws", "google",
                 "microsoft", "azure", "ovh", "hetzner", "linode", "vultr",
                 "leaseweb", "contabo", "oracle", "alibaba", "tencent")

_BL_NAMES = {"firehol_level1": "FireHOL level1 (aggregated abuse)",
             "tor_exit": "Tor exit node",
             "spamhaus_drop": "Spamhaus DROP (hijacked/criminal netblocks)",
             "blocklist_de": "blocklist.de (attack sources)"}


def _valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


async def run(ip: str) -> dict[str, Any]:
    """Assess an IP's reputation and whether it is a hosting/blocklisted IP."""
    ip = ip.strip()
    if not _valid_ip(ip):
        return {
            "check": "ip",
            "risk": RiskLevel.YELLOW,
            "summary": f"'{ip}' is not a valid IPv4/IPv6 address.",
            "findings": {"input": ip},
        }

    # 1) Local blocklists
    bl_status = await blocklists.ensure_fresh()
    bl_hits = blocklists.check_ip_local(ip)

    # 2) Local ASN / org lookup
    asn_status = await asn.ensure_fresh()
    info = asn.lookup(ip) or {}

    notes: list[str] = []
    unavailable = [str(n) for n, ok in {**bl_status, **asn_status}.items() if not ok]
    if unavailable:
        notes.append(f"Some datasets could not be refreshed: {', '.join(unavailable)} "
                     "(using cached copies if present).")

    risk = RiskLevel.GREEN
    summary_bits: list[str] = []

    # Blocklist verdict (strongest signal)
    if bl_hits:
        risk = RiskLevel.RED
        summary_bits.append("listed on: " + ", ".join(_BL_NAMES.get(h, h) for h in bl_hits))
    else:
        summary_bits.append("not on local blocklists")

    # Hosting/datacenter heuristic from AS description
    org = (info.get("org") or "")
    is_hosting = any(h in org.lower() for h in HOSTING_HINTS)
    if is_hosting:
        if risk == RiskLevel.GREEN:
            risk = RiskLevel.YELLOW
        summary_bits.append("hosting/datacenter ASN (unusual for a personal recruiter)")

    if not info:
        notes.append("IP not found in the iptoasn dataset (unrouted or very new).")

    return {
        "check": "ip",
        "risk": risk,
        "summary": "; ".join(summary_bits),
        "findings": {
            "ip": ip,
            "blocklist_hits": ", ".join(bl_hits) or None,
            "asn": info.get("asn"),
            "org": org or None,
            "country": info.get("country"),
            "is_tor": "tor_exit" in bl_hits,
            "hosting_datacenter": is_hosting,
        },
        "notes": notes,
    }
