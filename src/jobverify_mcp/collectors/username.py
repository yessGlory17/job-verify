"""Check a username across reliable, keyless platforms (identity footprint).

A curated, high-reliability subset (GitHub, Reddit, Keybase) rather than the
3000 flaky sites of Sherlock/Maigret. GitHub even exposes the account creation
date — a real age signal. A recruiter handle that exists nowhere, or only as a
brand-new account, is a sock-puppet signal. For broader coverage, let the agent
also web-search the username.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from ..common import RiskLevel, USER_AGENT

REQ_TIMEOUT = 12.0
_VALID = re.compile(r"^[A-Za-z0-9._-]{1,39}$")


async def _github(client: httpx.AsyncClient, u: str) -> dict[str, Any]:
    try:
        r = await client.get(f"https://api.github.com/users/{u}",
                             headers={"User-Agent": USER_AGENT,
                                      "Accept": "application/vnd.github+json"},
                             timeout=REQ_TIMEOUT)
        if r.status_code == 200:
            d = r.json()
            return {"exists": True, "url": d.get("html_url"),
                    "created": (d.get("created_at") or "")[:10],
                    "name": d.get("name"), "followers": d.get("followers")}
        return {"exists": False}
    except Exception:  # noqa: BLE001
        return {"exists": None}


async def _reddit(client: httpx.AsyncClient, u: str) -> dict[str, Any]:
    try:
        r = await client.get(f"https://www.reddit.com/user/{u}/about.json",
                             headers={"User-Agent": USER_AGENT},
                             timeout=REQ_TIMEOUT)
        if r.status_code == 200:
            d = r.json().get("data", {})
            return {"exists": True, "url": f"https://www.reddit.com/user/{u}",
                    "karma": d.get("total_karma")}
        if r.status_code == 404:
            return {"exists": False}
        return {"exists": None}
    except Exception:  # noqa: BLE001
        return {"exists": None}


async def _keybase(client: httpx.AsyncClient, u: str) -> dict[str, Any]:
    try:
        r = await client.get("https://keybase.io/_/api/1.0/user/lookup.json",
                             params={"usernames": u},
                             headers={"User-Agent": USER_AGENT},
                             timeout=REQ_TIMEOUT)
        if r.status_code == 200 and r.json().get("them"):
            return {"exists": True, "url": f"https://keybase.io/{u}"}
        return {"exists": False}
    except Exception:  # noqa: BLE001
        return {"exists": None}


async def run(username: str) -> dict[str, Any]:
    """Check where a username exists across GitHub, Reddit and Keybase."""
    username = username.strip().lstrip("@")
    if not _VALID.match(username):
        return {
            "check": "username",
            "risk": RiskLevel.YELLOW,
            "summary": f"'{username}' is not a plausible username.",
            "findings": {"input": username},
        }

    async with httpx.AsyncClient(follow_redirects=True) as client:
        gh = await _github(client, username)
        rd = await _reddit(client, username)
        kb = await _keybase(client, username)

    platforms = {"github": gh, "reddit": rd, "keybase": kb}
    found = {p: v for p, v in platforms.items() if v.get("exists") is True}

    notes = ["Also web-search the username for broader coverage. Name collisions "
             "happen — confirm the profile is actually the recruiter."]
    gh_created = gh.get("created") if gh.get("exists") else None
    if gh_created:
        notes.append(f"GitHub account created {gh_created} (real age signal).")

    if found:
        risk = RiskLevel.GREEN
        summary = f"Username found on: {', '.join(found)} — has some online history."
    else:
        risk = RiskLevel.YELLOW
        summary = ("Username not found on GitHub/Reddit/Keybase — thin footprint "
                   "(weak signal; the person may just not use these platforms).")

    return {
        "check": "username",
        "risk": risk,
        "summary": summary,
        "findings": {
            "username": username,
            "found_on": list(found),
            "github": gh if gh.get("exists") is not None else None,
            "reddit": rd if rd.get("exists") is not None else None,
            "keybase": kb if kb.get("exists") is not None else None,
        },
        "notes": notes,
    }
