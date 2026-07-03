"""Certificate Transparency lookup via crt.sh (free, no API key).

Every SSL cert is publicly logged. crt.sh exposes those logs, letting us see a
domain's whole certificate history and its subdomains. Useful signals:
  - Earliest certificate ~= how long the domain has had HTTPS (age corroboration).
  - A cert issued only hours/days ago on an otherwise unknown domain = fresh
    phishing infrastructure.
  - The set of subdomains that ever had a cert (attack-surface / infra mapping).

crt.sh is free but can be slow or briefly 5xx/404 — we retry.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

from ..common import RiskLevel, USER_AGENT, domain_from_input

CRTSH_URL = "https://crt.sh/"
REQ_TIMEOUT = 30.0
NEW_DAYS = 90


def _parse_dt(s: str) -> datetime | None:
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue
    return None


async def run(domain: str) -> dict[str, Any]:
    """Look up a domain's Certificate Transparency history on crt.sh."""
    d = domain_from_input(domain)
    rows = None
    last_err: Exception | None = None
    async with httpx.AsyncClient(follow_redirects=True) as client:
        for _ in range(3):
            try:
                resp = await client.get(CRTSH_URL,
                                        params={"q": d, "output": "json"},
                                        headers={"User-Agent": USER_AGENT},
                                        timeout=REQ_TIMEOUT)
                if resp.status_code == 200 and resp.text.strip():
                    rows = resp.json()
                    last_err = None
                    break
                last_err = Exception(f"HTTP {resp.status_code}")
            except Exception as e:  # noqa: BLE001 - retry then report
                last_err = e
    if rows is None:
        return {
            "check": "certificate_transparency",
            "risk": RiskLevel.UNKNOWN,
            "summary": f"crt.sh did not return data for '{d}' "
                       f"({last_err}); it is often transiently slow — retry later.",
            "findings": {"domain": d},
        }

    if not rows:
        return {
            "check": "certificate_transparency",
            "risk": RiskLevel.YELLOW,
            "summary": (f"No certificates ever logged for '{d}'. Unusual for an "
                        "established company (they use HTTPS) — possible new/parked."),
            "findings": {"domain": d, "certificates": 0},
        }

    not_befores = [dt for dt in (_parse_dt(r.get("not_before", "")) for r in rows) if dt]
    subdomains: set[str] = set()
    for r in rows:
        for name in (r.get("name_value", "") or "").split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name and "@" not in name:
                subdomains.add(name)

    earliest = min(not_befores) if not_befores else None
    latest = max(not_befores) if not_befores else None
    age_days = (datetime.now(timezone.utc) - earliest).days if earliest else None

    notes: list[str] = []
    if age_days is None:
        risk = RiskLevel.UNKNOWN
        summary = f"{len(rows)} cert entries but no parseable dates."
    elif age_days < NEW_DAYS:
        risk = RiskLevel.YELLOW
        summary = (f"First certificate only {age_days} days ago — fresh HTTPS "
                   "infrastructure, consistent with a newly stood-up scam site.")
    else:
        risk = RiskLevel.GREEN
        summary = (f"Certificate history spans {age_days // 365}+ years "
                   f"({len(subdomains)} subdomains seen) — established infrastructure.")
    notes.append("Cert age is a lower bound; cross-check with check_domain (RDAP).")

    return {
        "check": "certificate_transparency",
        "risk": risk,
        "summary": summary,
        "findings": {
            "domain": d,
            "certificates": len(rows),
            "earliest_cert": earliest.date().isoformat() if earliest else None,
            "latest_cert": latest.date().isoformat() if latest else None,
            "earliest_age_days": age_days,
            "subdomain_count": len(subdomains),
            "sample_subdomains": sorted(subdomains)[:15],
        },
        "notes": notes,
    }
