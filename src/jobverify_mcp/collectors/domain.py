"""Domain registration data via RDAP (the modern, free WHOIS replacement).

Uses the rdap.org bootstrap endpoint which redirects to the authoritative
RDAP server for the TLD. No API key required. Note: some ccTLDs (e.g. some
country domains) have not yet deployed RDAP and may return 404.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..common import RiskLevel, domain_from_input, handle_error, http_get_json

RDAP_BOOTSTRAP = "https://rdap.org/domain/"

# Domains younger than this (days) are treated as high-risk.
NEW_DOMAIN_DAYS = 90
YOUNG_DOMAIN_DAYS = 365


def _parse_event(events: list[dict], action: str) -> datetime | None:
    for ev in events or []:
        if ev.get("eventAction") == action and ev.get("eventDate"):
            raw = ev["eventDate"]
            try:
                # RDAP dates are ISO 8601, often with 'Z'
                return datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                continue
    return None


async def run(domain: str) -> dict[str, Any]:
    """Look up a domain's registration data and assess its age.

    Freshly registered domains posing as established companies are one of the
    strongest scam signals.
    """
    d = domain_from_input(domain)
    try:
        data = await http_get_json(RDAP_BOOTSTRAP + d)
    except Exception as e:
        return {
            "check": "domain",
            "risk": RiskLevel.UNKNOWN,
            "summary": handle_error(e, "domain/RDAP")
            + " (Some ccTLDs do not support RDAP yet.)",
            "findings": {"domain": d},
        }

    events = data.get("events", [])
    registered = _parse_event(events, "registration")
    expires = _parse_event(events, "expiration")
    updated = _parse_event(events, "last changed")

    # Registrar
    registrar = None
    for ent in data.get("entities", []):
        roles = ent.get("roles", [])
        if "registrar" in roles:
            vcard = ent.get("vcardArray")
            if vcard and len(vcard) > 1:
                for item in vcard[1]:
                    if item[0] == "fn":
                        registrar = item[3]
                        break
            registrar = registrar or ent.get("handle")

    age_days = None
    if registered:
        age_days = (datetime.now(timezone.utc) - registered).days

    notes: list[str] = []
    if age_days is None:
        risk = RiskLevel.UNKNOWN
        summary = "Registration date not available from RDAP for this domain."
    elif age_days < NEW_DOMAIN_DAYS:
        risk = RiskLevel.RED
        summary = (f"Domain registered only {age_days} days ago — a very strong "
                   "scam signal for a company claiming to be established.")
    elif age_days < YOUNG_DOMAIN_DAYS:
        risk = RiskLevel.YELLOW
        summary = f"Domain is relatively young ({age_days} days old). Verify further."
    else:
        risk = RiskLevel.GREEN
        summary = f"Domain is {age_days // 365} year(s) old — consistent with age claims."

    statuses = data.get("status", [])
    if any("client hold" in s.lower() or "server hold" in s.lower() for s in statuses):
        notes.append("Domain is on HOLD status — often abuse-related.")

    return {
        "check": "domain",
        "risk": risk,
        "summary": summary,
        "findings": {
            "domain": d,
            "registered": registered.date().isoformat() if registered else None,
            "age_days": age_days,
            "expires": expires.date().isoformat() if expires else None,
            "last_updated": updated.date().isoformat() if updated else None,
            "registrar": registrar,
            "status": ", ".join(statuses) if statuses else None,
        },
        "notes": notes,
    }
