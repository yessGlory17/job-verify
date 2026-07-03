"""Check a domain's email-authentication posture via DNS (SPF/DMARC), no key.

A domain with no SPF and no/weak DMARC (p=none) is easy to spoof — so a
"recruiter" email claiming to be from such a domain is easier to fake. Strong
DMARC (p=reject/quarantine) plus SPF means the sender is hard to impersonate.
"""

from __future__ import annotations

import re
from typing import Any

from ..common import RiskLevel, domain_from_input, resolve_records


async def _txt(name: str) -> list[str]:
    out: list[str] = []
    for r in await resolve_records(name, "TXT"):
        # join the (possibly chunked) TXT strings
        out.append("".join(s.decode() if isinstance(s, bytes) else s
                           for s in r.strings))
    return out


async def run(domain: str) -> dict[str, Any]:
    """Assess SPF and DMARC records for a domain (spoofability)."""
    d = domain_from_input(domain)

    spf_records = [t for t in await _txt(d) if t.lower().startswith("v=spf1")]
    dmarc_records = [t for t in await _txt(f"_dmarc.{d}")
                     if t.lower().startswith("v=dmarc1")]

    has_spf = bool(spf_records)
    dmarc_policy = None
    if dmarc_records:
        m = re.search(r"\bp=(\w+)", dmarc_records[0], re.IGNORECASE)
        dmarc_policy = m.group(1).lower() if m else "none"

    strong_dmarc = dmarc_policy in ("reject", "quarantine")

    reasons: list[str] = []
    if not has_spf:
        reasons.append("no SPF record")
    if not dmarc_records:
        reasons.append("no DMARC record")
    elif dmarc_policy == "none":
        reasons.append("DMARC policy is p=none (monitor only)")

    if has_spf and strong_dmarc:
        risk = RiskLevel.GREEN
        summary = (f"'{d}' publishes SPF and enforcing DMARC (p={dmarc_policy}) "
                   "— hard to spoof.")
    elif not has_spf and not dmarc_records:
        risk = RiskLevel.YELLOW
        summary = (f"'{d}' has neither SPF nor DMARC — trivially spoofable; a real "
                   "corporate domain usually publishes both.")
    else:
        risk = RiskLevel.YELLOW
        summary = f"'{d}' is spoofable: " + ", ".join(reasons) + "."

    return {
        "check": "domain_auth",
        "risk": risk,
        "summary": summary,
        "findings": {
            "domain": d,
            "spf": spf_records[0] if spf_records else None,
            "has_spf": has_spf,
            "dmarc_policy": dmarc_policy,
            "has_dmarc": bool(dmarc_records),
            "spoofable": not (has_spf and strong_dmarc),
        },
        "notes": ["DKIM cannot be checked without the selector; verify via headers "
                  "(parse_email_headers) instead."],
    }
