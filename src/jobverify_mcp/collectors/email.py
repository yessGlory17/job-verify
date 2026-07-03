"""Email reputation: disposable-domain list, free-provider check, MX lookup."""

from __future__ import annotations

import re
from typing import Any

from ..common import RiskLevel, resolve_records

# Free consumer mail providers — legitimate companies rarely recruit from these.
FREE_PROVIDERS = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "hotmail.com",
    "outlook.com", "live.com", "aol.com", "icloud.com", "me.com", "gmx.com",
    "mail.com", "yandex.com", "yandex.ru", "protonmail.com", "proton.me",
    "zoho.com", "hey.com", "hotmail.co.uk", "yahoo.co.uk",
}

# Small starter set of known disposable/temporary-mail domains. Extend via
# a fuller list (e.g. github.com/disposable-email-domains) in production.
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "temp-mail.org",
    "tempmail.com", "throwawaymail.com", "yopmail.com", "getnada.com",
    "sharklasers.com", "trashmail.com", "maildrop.cc", "dispostable.com",
    "fakeinbox.com", "mailnesia.com", "mohmal.com", "emailondeck.com",
    "tempmailo.com", "mintemail.com", "spam4.me", "grr.la",
}

_EMAIL_RE = re.compile(r"^[^@\s]+@([^@\s]+\.[^@\s]+)$")


async def _has_mx(domain: str) -> tuple[bool, list[str]]:
    """Return (has_mx, mx_hosts); ([], False) if the domain has no MX."""
    answers = await resolve_records(domain, "MX")
    if not answers:
        return False, []
    hosts = sorted(str(r.exchange).rstrip(".") for r in answers)
    return True, hosts


async def run(email: str, company_domain: str | None = None) -> dict[str, Any]:
    """Assess an email address used by a purported recruiter.

    company_domain: if the recruiter claims to work at a company, pass that
    company's real domain to check whether the email matches it.
    """
    email = email.strip().lower()
    m = _EMAIL_RE.match(email)
    if not m:
        return {
            "check": "email",
            "risk": RiskLevel.RED,
            "summary": f"'{email}' is not a syntactically valid email address.",
            "findings": {"input": email},
        }
    domain = m.group(1)
    notes: list[str] = []
    findings: dict[str, Any] = {"email": email, "domain": domain}

    is_disposable = domain in DISPOSABLE_DOMAINS
    is_free = domain in FREE_PROVIDERS
    has_mx, mx_hosts = await _has_mx(domain)
    findings["mx_records"] = ", ".join(mx_hosts[:5]) if mx_hosts else None

    # Domain vs claimed company mismatch
    mismatch = None
    if company_domain:
        cd = company_domain.strip().lower().lstrip("@")
        # strip leading www.
        cd = re.sub(r"^www\.", "", cd)
        mismatch = (domain != cd) and (not domain.endswith("." + cd))
        findings["claimed_company_domain"] = cd
        findings["matches_company"] = not mismatch

    if is_disposable:
        risk = RiskLevel.RED
        summary = "Disposable/temporary email domain — very strong scam signal."
    elif not has_mx:
        risk = RiskLevel.RED
        summary = "Domain has no MX record — cannot receive mail; likely fake."
    elif mismatch:
        risk = RiskLevel.RED
        summary = (f"Email domain '{domain}' does NOT match the claimed company "
                   f"'{findings.get('claimed_company_domain')}'.")
    elif is_free:
        risk = RiskLevel.YELLOW
        summary = ("Free consumer mail provider — legitimate corporate recruiters "
                   "usually use a company domain.")
    else:
        risk = RiskLevel.GREEN
        summary = f"Custom domain '{domain}' with valid MX records."
        notes.append("Domain age/reputation still worth checking via check_domain.")

    return {
        "check": "email",
        "risk": risk,
        "summary": summary,
        "findings": findings,
        "notes": notes,
    }
