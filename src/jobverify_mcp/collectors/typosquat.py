"""Detect lookalike / typosquatting / homograph domains (offline, no key).

Scam recruiters register domains that mimic a real brand: 'microsofthr.com',
'google-careers.top', 'linkedln.com', or IDN homographs using confusable Unicode
letters. This checks a domain against a list of commonly impersonated brands
(plus an optional claimed-company brand) and flags high-abuse TLDs.
"""

from __future__ import annotations

import re
from typing import Any

from ..common import RiskLevel, domain_from_input, split_domain

# Commonly impersonated brands in job / recruiter scams.
COMMON_BRANDS = {
    "google", "microsoft", "apple", "amazon", "meta", "facebook", "linkedin",
    "netflix", "paypal", "upwork", "indeed", "glassdoor", "ziprecruiter",
    "deloitte", "accenture", "oracle", "ibm", "intel", "nvidia", "tesla",
    "spotify", "uber", "coinbase", "binance", "revolut", "wise", "stripe",
    "adobe", "cisco", "salesforce", "samsung", "huawei", "capgemini", "infosys",
}

# High-abuse / cheap TLDs frequently used for throwaway scam domains.
SUSPICIOUS_TLDS = {
    "top", "xyz", "icu", "online", "site", "click", "work", "live", "cyou",
    "sbs", "rest", "quest", "monster", "buzz", "fit", "gq", "ml", "cf", "ga",
    "tk", "zip", "mov", "shop", "store", "club", "life", "world", "support",
}


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


async def run(domain: str, brand: str | None = None) -> dict[str, Any]:
    """Assess whether a domain impersonates a known or claimed brand.

    brand: optionally the claimed company's name to compare against directly.
    """
    domain = domain_from_input(domain)

    core, tld = split_domain(domain)
    tokens = [t for t in re.split(r"[-_.]", core) if t]

    red: list[str] = []
    yellow: list[str] = []

    # 1) Homograph / IDN
    is_punycode = "xn--" in domain
    has_nonascii = any(ord(c) > 127 for c in domain)
    if is_punycode or has_nonascii:
        red.append("IDN/homograph domain (uses punycode or non-ASCII confusables)")

    # 2) Digit-for-letter substitution within a token (rn->m, 0->o, 1->l style)
    #    handled via levenshtein below against brands.

    brands = set(COMMON_BRANDS)
    claimed = None
    if brand:
        claimed = re.sub(r"[^a-z0-9]", "", brand.strip().lower())
        if claimed:
            brands.add(claimed)

    matched_brand = None
    for b in brands:
        if not b:
            continue
        # exact brand as one of several tokens (e.g. 'google-careers', 'linkedin-verify')
        if b in tokens and core != b:
            matched_brand = b
            red.append(f"brand '{b}' embedded with extra words → impersonation")
            break
        # whole core is a near-miss typo of the brand (e.g. 'gooogle', 'linkedln')
        # only for brands >= 5 chars to avoid false positives on short names.
        dist = _levenshtein(core, b)
        if len(b) >= 5 and 0 < dist <= 2 and abs(len(core) - len(b)) <= 2:
            matched_brand = b
            red.append(f"'{core}' is {dist} edit(s) from brand '{b}' → typosquat")
            break
        # brand substring inside a longer glued core (e.g. 'microsofthr')
        if b in core and core != b and len(core) - len(b) <= 6:
            matched_brand = b
            yellow.append(f"brand '{b}' embedded in '{core}'")
            break

    # 3) Suspicious TLD
    if tld in SUSPICIOUS_TLDS:
        msg = f"high-abuse TLD '.{tld}'"
        (red if matched_brand else yellow).append(msg)

    if red:
        risk = RiskLevel.RED
        summary = "Likely impersonation: " + "; ".join(red)
    elif yellow:
        risk = RiskLevel.YELLOW
        summary = "Suspicious: " + "; ".join(yellow)
    else:
        risk = RiskLevel.GREEN
        summary = f"No lookalike/typosquat signal for '{domain}'."

    return {
        "check": "typosquatting",
        "risk": risk,
        "summary": summary,
        "findings": {
            "domain": domain,
            "core": core,
            "tld": tld,
            "matched_brand": matched_brand,
            "claimed_brand": claimed,
            "punycode_or_nonascii": is_punycode or has_nonascii,
            "suspicious_tld": tld in SUSPICIOUS_TLDS,
            "red_flags": red,
            "yellow_flags": yellow,
        },
        "notes": ["Pair with check_domain (age) — impersonation domains are usually "
                  "newly registered."],
    }
