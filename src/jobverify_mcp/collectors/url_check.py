"""URL/domain safety checks — 100% key-free, open data only.

  - Phishing.Database (mitchellkrogza, MIT license): ~390k active phishing
    domains, refreshed daily and checked locally.
  - URLhaus recent feed (abuse.ch): recent malicious/malware URLs, downloaded
    without any auth key and matched at host level.

Dropped sources (all needed keys and/or restricted commercial use):
  - Google Safe Browsing (v4 deprecated, non-commercial, Google Cloud key)
  - URLhaus *API* (requires an Auth-Key since 2025-06-30 — we use the keyless
    downloadable feed instead)
  - PhishTank (closed to new registrations since 2020)

Results are aggregated: if ANY source flags the URL/domain, overall risk is RED.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from ..common import RiskLevel
from . import blocklists


def _extract_domain(url: str) -> str:
    host = urlparse(url).hostname or ""
    return host.lower().lstrip(".")


async def run(url: str) -> dict[str, Any]:
    """Check a URL/domain against local phishing + malware blocklists (no key)."""
    url = url.strip()
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url
    domain = _extract_domain(url)

    notes: list[str] = []
    flagged_by: list[str] = []

    # 1) Phishing domains (Phishing.Database)
    dl_status = await blocklists.ensure_fresh_domains()
    if domain and blocklists.check_domain_local(domain):
        flagged_by.append("Phishing.Database")

    # 2) Malware URLs (URLhaus recent feed)
    uh_ok = await blocklists.ensure_fresh_urlhaus()
    if domain and uh_ok and blocklists.check_url_host(domain):
        flagged_by.append("URLhaus")

    for n, ok in dl_status.items():
        if not ok:
            notes.append(f"Local blocklist '{n}' could not be refreshed "
                         "(using cached copy if present).")
    if not uh_ok:
        notes.append("URLhaus feed could not be refreshed (using cache if present).")

    if flagged_by:
        risk = RiskLevel.RED
        summary = f"URL/domain flagged as malicious/phishing by: {', '.join(flagged_by)}."
    else:
        risk = RiskLevel.GREEN
        summary = "No local phishing/malware list flagged this URL."

    return {
        "check": "url",
        "risk": risk,
        "summary": summary,
        "findings": {
            "url": url,
            "domain": domain or None,
            "flagged_by": ", ".join(flagged_by) or None,
            "in_phishing_database": "Phishing.Database" in flagged_by,
            "in_urlhaus": "URLhaus" in flagged_by,
        },
        "notes": notes,
    }
