"""Email digital-footprint check via Gravatar (free, no API key).

A quick, reliable, alert-free OSINT signal: does this email have a public
identity attached to it? Gravatar returns a profile — including linked social
accounts, name and location — for emails people actually use professionally.
A throwaway/scam email typically has no Gravatar and no linked accounts.

(This is a reliable keyless subset of tools like holehe. It does NOT probe
password-reset endpoints across 120 sites; it uses one clean, public endpoint.)
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

import httpx

from ..common import RiskLevel, USER_AGENT

GRAVATAR_URL = "https://gravatar.com/{hash}.json"
REQ_TIMEOUT = 15.0
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


async def run(email: str) -> dict[str, Any]:
    """Look up an email's public Gravatar profile and linked accounts."""
    email = email.strip().lower()
    if not _EMAIL_RE.match(email):
        return {
            "check": "email_footprint",
            "risk": RiskLevel.YELLOW,
            "summary": f"'{email}' is not a valid email address.",
            "findings": {"input": email},
        }

    md5 = hashlib.md5(email.encode()).hexdigest()
    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            resp = await client.get(GRAVATAR_URL.format(hash=md5),
                                    headers={"User-Agent": USER_AGENT},
                                    timeout=REQ_TIMEOUT)
    except Exception as e:  # noqa: BLE001
        return {
            "check": "email_footprint",
            "risk": RiskLevel.UNKNOWN,
            "summary": f"Gravatar lookup failed: {type(e).__name__}.",
            "findings": {"email": email},
        }

    if resp.status_code == 404:
        return {
            "check": "email_footprint",
            "risk": RiskLevel.YELLOW,
            "summary": ("No Gravatar profile for this email — weak digital footprint. "
                        "Common for throwaway/scam addresses (but also for many "
                        "ordinary users), so treat as a soft signal."),
            "findings": {"email": email, "has_gravatar": False},
        }
    if resp.status_code != 200:
        return {
            "check": "email_footprint",
            "risk": RiskLevel.UNKNOWN,
            "summary": f"Gravatar returned HTTP {resp.status_code}.",
            "findings": {"email": email},
        }

    try:
        entry = (resp.json().get("entry") or [{}])[0]
    except Exception:  # noqa: BLE001
        entry = {}

    accounts = [a.get("url") or a.get("domain")
                for a in (entry.get("accounts") or []) if isinstance(a, dict)]
    display = entry.get("displayName") or (entry.get("name") or {}).get("formatted")

    return {
        "check": "email_footprint",
        "risk": RiskLevel.GREEN,
        "summary": (f"Gravatar profile exists ({len(accounts)} linked account(s)). "
                    "An established online identity is a mild legitimacy signal — "
                    "but verify the linked accounts actually match the recruiter."),
        "findings": {
            "email": email,
            "has_gravatar": True,
            "display_name": display,
            "location": entry.get("currentLocation"),
            "linked_accounts": [a for a in accounts if a],
            "profile_url": entry.get("profileUrl"),
        },
        "notes": ["A Gravatar can be created by anyone; corroborate the linked "
                  "accounts rather than trusting existence alone."],
    }
