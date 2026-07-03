"""Proactively find registered look-alike domains (dnstwist-style, no key).

Given a real brand domain, generate typo/homoglyph/TLD permutations OFFLINE, then
check which ones actually resolve in DNS (i.e. are registered and live). Live
look-alikes of a brand are prime phishing / fake-recruiter infrastructure.

All keyless: permutation generation is local; resolution uses DNS.
"""

from __future__ import annotations

import asyncio
from typing import Any

import dns.asyncresolver

from ..common import RiskLevel, domain_from_input, resolve_records, split_domain

_KEYBOARD = {
    "a": "qsz", "b": "vgn", "c": "xdv", "d": "sfe", "e": "wrd", "f": "dgr",
    "g": "fht", "h": "gjy", "i": "uok", "j": "hku", "k": "jli", "l": "ko",
    "m": "n", "n": "bm", "o": "ipl", "p": "o", "q": "wa", "r": "et", "s": "adw",
    "t": "ry", "u": "yi", "v": "cb", "w": "qe", "x": "zc", "y": "tu", "z": "xas",
}
_HOMOGLYPH = {"o": "0", "0": "o", "l": "1", "1": "l", "i": "1", "e": "3",
              "a": "4", "s": "5"}
_EXTRA_TLDS = ["com", "net", "org", "co", "io", "info", "top", "xyz", "online",
               "site", "careers", "jobs", "app"]
_ADDON_WORDS = ["careers", "career", "jobs", "hr", "recruiting", "verify",
                "secure", "portal", "apply", "team", "hiring", "official"]

MAX_CANDIDATES = 300
CONCURRENCY = 25
DNS_LIFETIME = 4.0


def _permutations(core: str, tld: str) -> set[str]:
    out: set[str] = set()

    # omission
    for i in range(len(core)):
        out.add(core[:i] + core[i + 1:] + "." + tld)
    # repetition
    for i in range(len(core)):
        out.add(core[:i] + core[i] + core[i:] + "." + tld)
    # transposition
    for i in range(len(core) - 1):
        out.add(core[:i] + core[i + 1] + core[i] + core[i + 2:] + "." + tld)
    # keyboard replacement
    for i, ch in enumerate(core):
        for r in _KEYBOARD.get(ch, ""):
            out.add(core[:i] + r + core[i + 1:] + "." + tld)
    # homoglyph
    for i, ch in enumerate(core):
        if ch in _HOMOGLYPH:
            out.add(core[:i] + _HOMOGLYPH[ch] + core[i + 1:] + "." + tld)
    # hyphenation
    for i in range(1, len(core)):
        out.add(core[:i] + "-" + core[i:] + "." + tld)
    # tld swap (same core)
    for t in _EXTRA_TLDS:
        if t != tld:
            out.add(core + "." + t)
    # addon words (common recruiter lures)
    for w in _ADDON_WORDS:
        out.add(f"{core}-{w}.{tld}")
        out.add(f"{core}{w}.{tld}")

    out.discard(core + "." + tld)  # the original
    return out


async def _resolves(name: str, sem: asyncio.Semaphore,
                    resolver: dns.asyncresolver.Resolver) -> str | None:
    async with sem:
        return name if await resolve_records(name, "A", resolver=resolver) else None


async def run(domain: str, max_checks: int = MAX_CANDIDATES) -> dict[str, Any]:
    """Generate look-alikes of a real domain and return those that resolve.

    domain: the REAL brand domain to protect (e.g. 'stripe.com').
    max_checks: cap on how many permutations to DNS-resolve (default 300).
    """
    domain = domain_from_input(domain)
    core, tld = split_domain(domain)
    if not core or not tld:
        return {
            "check": "lookalike_domains",
            "risk": RiskLevel.YELLOW,
            "summary": f"'{domain}' is not a valid domain.",
            "findings": {"input": domain},
        }

    candidates = sorted(_permutations(core, tld))[:max(1, min(max_checks, 600))]
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = DNS_LIFETIME
    sem = asyncio.Semaphore(CONCURRENCY)
    results = await asyncio.gather(*(_resolves(c, sem, resolver) for c in candidates))
    live = sorted(x for x in results if x)

    if live:
        risk = RiskLevel.RED if len(live) >= 3 else RiskLevel.YELLOW
        summary = (f"{len(live)} registered look-alike domain(s) of '{domain}' are "
                   f"live (of {len(candidates)} permutations checked). Any of these "
                   "could host a fake-recruiter site.")
    else:
        risk = RiskLevel.GREEN
        summary = (f"No live look-alike domains found among {len(candidates)} "
                   "permutations checked.")

    return {
        "check": "lookalike_domains",
        "risk": risk,
        "summary": summary,
        "findings": {
            "domain": domain,
            "permutations_checked": len(candidates),
            "live_lookalikes": live,
            "live_count": len(live),
        },
        "notes": ["Resolving ≠ malicious by itself; feed each hit to check_domain "
                  "(age), check_url (phishing), and fetch_archived_page. Coverage is "
                  "a bounded subset of all possible permutations."],
    }
