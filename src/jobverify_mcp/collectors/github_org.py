"""Verify a company's GitHub organization (free, no key).

For tech companies, a real GitHub org whose website points back to the company
domain (and that has history + repos) is a solid legitimacy signal. A scam
"tech company" usually has none, or an org whose website doesn't match.

Bidirectional check:
  - org -> site: this tool reads the org's `blog` (website) via the GitHub API.
  - site -> org: fetch the company's website (agent's WebFetch) and see if it
    links to this org. (Left to the agent; not done here.)
"""

from __future__ import annotations

from typing import Any

import httpx

from ..common import (RiskLevel, USER_AGENT, domain_core, handle_error,
                      registrable)

API = "https://api.github.com"
REQ_TIMEOUT = 15.0
_HEADERS = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}


async def _get(client: httpx.AsyncClient, path: str) -> Any:
    r = await client.get(f"{API}{path}", headers=_HEADERS, timeout=REQ_TIMEOUT)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()


async def run(org_or_name: str, expected_domain: str | None = None) -> dict[str, Any]:
    """Look up a GitHub org and check its website against the company domain.

    org_or_name: a GitHub org handle (e.g. 'stripe') or a company name to search.
    expected_domain: the company's real domain to compare the org website against.
    """
    handle = org_or_name.strip().lstrip("@")
    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            org = await _get(client, f"/orgs/{handle}")
            searched = False
            if org is None:
                searched = True
                res = await client.get(
                    f"{API}/search/users",
                    params={"q": f"{org_or_name} type:org", "per_page": 5},
                    headers=_HEADERS, timeout=REQ_TIMEOUT)
                res.raise_for_status()
                items = res.json().get("items", [])
                if items:
                    org = await _get(client, f"/orgs/{items[0]['login']}")
    except Exception as e:  # noqa: BLE001
        return {
            "check": "github_org",
            "risk": RiskLevel.UNKNOWN,
            "summary": handle_error(e, "github_org"),
            "findings": {"query": org_or_name},
        }

    if not org:
        return {
            "check": "github_org",
            "risk": RiskLevel.YELLOW,
            "summary": (f"No GitHub organization found for '{org_or_name}'. Weak signal "
                        "for non-tech companies, but notable if they claim to build tech."),
            "findings": {"query": org_or_name, "found": False},
        }

    blog = org.get("blog") or ""
    org_domain = registrable(blog) if blog else None
    domain_match = None
    if expected_domain and org_domain:
        # Match on brand core so stripe.dev ~ stripe.com counts as the same brand.
        domain_match = (domain_core(blog) == domain_core(expected_domain))

    repos = org.get("public_repos") or 0
    created = (org.get("created_at") or "")[:10]

    if domain_match:
        risk = RiskLevel.GREEN
        summary = (f"GitHub org '{org.get('login')}' website ({org_domain}) matches the "
                   f"company domain — created {created}, {repos} public repos. Strong signal.")
    elif domain_match is False:
        risk = RiskLevel.YELLOW
        summary = (f"GitHub org '{org.get('login')}' exists but its website ({org_domain}) "
                   f"does NOT match the claimed domain ({registrable(expected_domain)}).")
    else:
        risk = RiskLevel.GREEN if repos > 0 else RiskLevel.YELLOW
        summary = (f"GitHub org '{org.get('login')}' found (created {created}, {repos} "
                   "repos). Provide expected_domain to confirm the website matches.")

    return {
        "check": "github_org",
        "risk": risk,
        "summary": summary,
        "findings": {
            "login": org.get("login"),
            "name": org.get("name"),
            "website": blog or None,
            "website_domain": org_domain,
            "domain_matches_company": domain_match,
            "created": created,
            "public_repos": repos,
            "followers": org.get("followers"),
            "found_via_search": searched,
        },
        "notes": ["Also check the reverse: does the company's website link to this org? "
                  "(fetch the site and look for github.com/<org>)."],
    }
