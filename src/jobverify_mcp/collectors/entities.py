"""Extract structured entities from a raw recruiter message (offline, no key).

Turns free text into the concrete identifiers the other tools consume:
emails, URLs, domains, phone numbers, IPs, crypto addresses, and LinkedIn URLs.
This makes the agent reliable — it never misses an entity buried in the text.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

import phonenumbers

from ..common import RiskLevel

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_URL_RE = re.compile(r"\b(?:https?://|www\.)[^\s<>\"'`\])}]+", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b")
# Crypto: BTC (legacy/segwit/bech32) and ETH
_BTC_RE = re.compile(r"\b(?:bc1[ac-hj-np-z0-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,39})\b")
_ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

# Off-platform contact keywords often used to move victims away from LinkedIn.
_OFFPLATFORM_RE = re.compile(
    r"\b(whatsapp|telegram|signal|wechat|skype|t\.me|wa\.me)\b", re.IGNORECASE)


def _clean_url(u: str) -> str:
    u = u.rstrip(".,);]!?'\"")
    if u.lower().startswith("www."):
        u = "http://" + u
    return u


def _domain_of(url: str) -> str | None:
    host = urlparse(url).hostname
    return host.lower() if host else None


async def run(text: str, default_region: str | None = None) -> dict[str, Any]:
    """Parse a raw message into structured, de-duplicated entities.

    default_region: ISO code (e.g. 'TR', 'US') to help find local phone numbers
    written without a '+' country prefix.
    """
    emails = sorted({m.group(0).lower() for m in _EMAIL_RE.finditer(text)})

    urls = sorted({_clean_url(m.group(0)) for m in _URL_RE.finditer(text)})
    linkedin = sorted({u for u in urls if "linkedin.com" in u.lower()})

    domains: set[str] = set()
    for u in urls:
        d = _domain_of(u)
        if d:
            domains.add(d)
    for e in emails:
        domains.add(e.split("@")[-1])

    ips: set[str] = set()
    for m in list(_IPV4_RE.finditer(text)) + list(_IPV6_RE.finditer(text)):
        try:
            ipaddress.ip_address(m.group(0))
            ips.add(m.group(0))
        except ValueError:
            continue

    phones: set[str] = set()
    for match in phonenumbers.PhoneNumberMatcher(text, default_region):
        phones.add(phonenumbers.format_number(
            match.number, phonenumbers.PhoneNumberFormat.E164))

    crypto = sorted({m.group(0) for m in _BTC_RE.finditer(text)}
                    | {m.group(0) for m in _ETH_RE.finditer(text)})

    offplatform = sorted({m.group(0).lower() for m in _OFFPLATFORM_RE.finditer(text)})

    findings = {
        "emails": emails,
        "domains": sorted(domains),
        "urls": urls,
        "linkedin_urls": linkedin,
        "phones": sorted(phones),
        "ips": sorted(ips),
        "crypto_addresses": crypto,
        "offplatform_mentions": offplatform,
    }
    counts = {k: len(v) for k, v in findings.items()}

    # Light risk hint: crypto request or off-platform push are notable on their own.
    notes = ["Feed these entities into the specific check_* tools."]
    if crypto:
        risk = RiskLevel.RED
        summary = "Crypto address present — advance-fee / payment scam pattern."
    elif offplatform:
        risk = RiskLevel.YELLOW
        summary = ("Off-platform contact requested "
                   f"({', '.join(offplatform)}) — common scam tactic.")
    else:
        risk = RiskLevel.UNKNOWN
        summary = (f"Extracted {counts['emails']} email(s), {counts['urls']} URL(s), "
                   f"{counts['phones']} phone(s), {counts['ips']} IP(s).")

    return {
        "check": "entities",
        "risk": risk,
        "summary": summary,
        "findings": {**findings, "counts": counts},
        "notes": notes,
    }
