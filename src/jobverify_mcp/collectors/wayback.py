"""Wayback Machine history — a LEGAL proxy for 'how long has this existed'.

LinkedIn does not expose account creation dates. But the Internet Archive can
tell us when a profile/company/website URL was first archived, giving a lower
bound on its age. Newly created scam profiles have no archive history.

Uses the lightweight `archive.org/wayback/available` endpoint (fast, reliable):
querying with an early target timestamp returns the closest snapshot, which is
effectively the FIRST capture; querying with 'now' returns the LATEST capture.
No API key required.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

from ..common import RiskLevel, USER_AGENT, handle_error

AVAILABLE_API = "https://archive.org/wayback/available"
REQ_TIMEOUT = 20.0

NEW_DAYS = 90
YOUNG_DAYS = 365


def _parse_ts(ts: str) -> datetime | None:
    try:
        return datetime.strptime(ts, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


async def _closest(client: httpx.AsyncClient, url: str, target: str) -> dict | None:
    """Return the archived_snapshots.closest dict nearest to `target` ts, or None."""
    resp = await client.get(AVAILABLE_API,
                            params={"url": url, "timestamp": target},
                            headers={"User-Agent": USER_AGENT},
                            timeout=REQ_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    return (data.get("archived_snapshots") or {}).get("closest")


async def run(url: str) -> dict[str, Any]:
    """Check the Internet Archive history of a URL (e.g. a LinkedIn profile).

    Returns first/last capture dates. Interpret a missing or very recent first
    capture as a signal the profile/site may be new.
    """
    url = url.strip()
    now_ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            first_snap = await _closest(client, url, "19960101000000")
            last_snap = await _closest(client, url, now_ts)
    except Exception as e:
        return {
            "check": "wayback",
            "risk": RiskLevel.UNKNOWN,
            "summary": handle_error(e, "wayback"),
            "findings": {"url": url},
        }

    if not first_snap:
        return {
            "check": "wayback",
            "risk": RiskLevel.YELLOW,
            "summary": ("No Internet Archive snapshots found. The URL may be new, "
                        "private, or never indexed — suspicious for a supposedly "
                        "established profile/company, but not conclusive."),
            "findings": {"url": url, "snapshots": 0},
        }

    first = _parse_ts(first_snap.get("timestamp", ""))
    last = _parse_ts((last_snap or {}).get("timestamp", "")) or first

    notes = ["Archive age is a LOWER bound on real age, not the creation date."]
    if first:
        age_days = (datetime.now(timezone.utc) - first).days
        if age_days < NEW_DAYS:
            risk = RiskLevel.YELLOW
            summary = f"First archived only {age_days} days ago — the URL appears new."
        elif age_days < YOUNG_DAYS:
            risk = RiskLevel.YELLOW
            summary = f"First archived {age_days} days ago — relatively recent."
        else:
            risk = RiskLevel.GREEN
            summary = (f"Archived since {first.date().isoformat()} "
                       f"({age_days // 365}+ years) — consistent with an established page.")
    else:
        risk = RiskLevel.UNKNOWN
        summary = "A snapshot exists but its timestamp could not be parsed."
        age_days = None

    return {
        "check": "wayback",
        "risk": risk,
        "summary": summary,
        "findings": {
            "url": url,
            "first_capture": first.date().isoformat() if first else None,
            "last_capture": last.date().isoformat() if last else None,
            "first_capture_age_days": age_days,
        },
        "notes": notes,
    }
