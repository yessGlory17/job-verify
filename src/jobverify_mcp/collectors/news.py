"""Search regional/local news for a company via Google News RSS (free, no key).

For small companies that GLEIF/SEC don't cover, a real firm usually leaves *some*
news/press footprint in its region — and, crucially, any news that itself flags
the company as a scam is a decisive signal. Google News RSS is keyless and
supports country/language targeting for regional coverage.

Locating the company FIRST matters: searching the wrong region (or a hardcoded
default) silently hides real local coverage and produces a misleading "no news"
result. The region is therefore taken from an explicit `country`, or derived from
the company's own domain ccTLD; if neither is known, the search is run
region-neutral and the result flags that local targeting was skipped.
"""

from __future__ import annotations

import re
from typing import Any
from xml.etree import ElementTree

import httpx

from ..common import (RiskLevel, USER_AGENT, domain_from_input, handle_error,
                      split_domain)

RSS_URL = "https://news.google.com/rss/search"
REQ_TIMEOUT = 20.0
_SCAM_WORDS = re.compile(r"\b(scam|fraud|fraudulent|phishing|fake|lawsuit|"
                         r"charged|indict|arrest|dolandır|sahte|sahtekar)\b",
                         re.IGNORECASE)

# Country-code TLD -> (Google News country code, primary language). Used to
# regionally target the search from the company's own domain when no explicit
# country is supplied. Generic TLDs (com/net/org/io…) carry no location.
_CCTLD: dict[str, tuple[str, str]] = {
    "tr": ("TR", "tr"), "de": ("DE", "de"), "fr": ("FR", "fr"),
    "es": ("ES", "es"), "it": ("IT", "it"), "nl": ("NL", "nl"),
    "pt": ("PT", "pt"), "br": ("BR", "pt"), "ru": ("RU", "ru"),
    "pl": ("PL", "pl"), "se": ("SE", "sv"), "no": ("NO", "no"),
    "dk": ("DK", "da"), "fi": ("FI", "fi"), "gr": ("GR", "el"),
    "cz": ("CZ", "cs"), "ro": ("RO", "ro"), "hu": ("HU", "hu"),
    "jp": ("JP", "ja"), "cn": ("CN", "zh"), "kr": ("KR", "ko"),
    "in": ("IN", "en"), "id": ("ID", "id"), "th": ("TH", "th"),
    "vn": ("VN", "vi"), "sa": ("SA", "ar"), "ae": ("AE", "ar"),
    "eg": ("EG", "ar"), "il": ("IL", "he"), "mx": ("MX", "es"),
    "ar": ("AR", "es"), "cl": ("CL", "es"), "co": ("CO", "es"),
    "za": ("ZA", "en"), "ng": ("NG", "en"), "ca": ("CA", "en"),
    "au": ("AU", "en"), "nz": ("NZ", "en"), "ie": ("IE", "en"),
    "ch": ("CH", "de"), "at": ("AT", "de"), "be": ("BE", "nl"),
    "uk": ("GB", "en"), "gb": ("GB", "en"), "us": ("US", "en"),
}
_CC_LANG: dict[str, str] = {cc: lang for cc, lang in _CCTLD.values()}


def _country_from_domain(company_domain: str | None) -> str | None:
    """Infer the company's country from its domain's ccTLD, or None if generic."""
    if not company_domain:
        return None
    _, tld = split_domain(domain_from_input(company_domain))
    entry = _CCTLD.get(tld)
    return entry[0] if entry else None


async def run(company: str, country: str | None = None,
              language: str | None = None,
              company_domain: str | None = None) -> dict[str, Any]:
    """Search news for a company, targeted to its region.

    country: ISO-2 code (e.g. 'TR', 'DE') — the company's actual country. If
        omitted, it is inferred from ``company_domain``'s ccTLD.
    language: ISO-2 language (e.g. 'tr', 'en'); defaults from the country.
    company_domain: the company's website/email domain, used to derive the
        region from its ccTLD when ``country`` is not given.

    If the location cannot be determined, the search runs region-neutral rather
    than assuming a default country, and the result marks that local targeting
    was skipped (so a "no news" outcome is NOT read as a thin footprint).
    """
    cc = (country or _country_from_domain(company_domain) or "").upper()
    lang = (language or _CC_LANG.get(cc) or "en").lower()
    targeted = bool(cc)

    query = f'"{company}"'
    if targeted:
        params = {"q": query, "hl": f"{lang}-{cc}", "gl": cc, "ceid": f"{cc}:{lang}"}
    else:
        # No known region: search language-neutral (no gl/ceid) instead of
        # defaulting to one country, which would hide real local coverage.
        params = {"q": query, "hl": lang}

    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            resp = await client.get(RSS_URL, params=params,
                                    headers={"User-Agent": USER_AGENT},
                                    timeout=REQ_TIMEOUT)
            resp.raise_for_status()
            root = ElementTree.fromstring(resp.content)
    except Exception as e:  # noqa: BLE001
        return {
            "check": "company_news",
            "risk": RiskLevel.UNKNOWN,
            "summary": handle_error(e, "news"),
            "findings": {"company": company},
        }

    items = []
    for item in root.iter("item"):
        title = (item.findtext("title") or "").strip()
        source_el = item.find("source")
        items.append({
            "title": title,
            "source": (source_el.text if source_el is not None else None),
            "date": (item.findtext("pubDate") or "")[:16],
            "link": item.findtext("link"),
        })
        if len(items) >= 12:
            break

    scam_hits = [it for it in items if _SCAM_WORDS.search(it["title"])]
    where = f"in {cc}" if targeted else "(no region targeted)"

    notes = ["Google News coverage skews to indexed outlets; local small-business "
             "news may be missing. Cross-check with a general web search."]

    if scam_hits:
        risk = RiskLevel.RED
        summary = (f"{len(scam_hits)} news headline(s) mention scam/fraud/legal terms "
                   f"for '{company}' — investigate these directly.")
    elif items:
        risk = RiskLevel.GREEN
        summary = (f"{len(items)} news result(s) for '{company}' {where} — has a media "
                   "footprint (read them; presence ≠ legitimacy by itself).")
    elif targeted:
        risk = RiskLevel.YELLOW
        summary = (f"No news found for '{company}' in {cc}. Thin footprint — unusual "
                   "for an established firm, though very small/new firms may have none.")
    else:
        # Absence of results is inconclusive when we never targeted the right region.
        risk = RiskLevel.UNKNOWN
        summary = (f"No news for '{company}' in a region-neutral search. Determine the "
                   "company's country first (from its address, domain ccTLD, or a web "
                   "search) and re-run with `country` for a meaningful local check.")
        notes.insert(0, "Location unknown — result is inconclusive, not a thin-footprint "
                        "signal. Pass `country` or `company_domain` to target the region.")

    return {
        "check": "company_news",
        "risk": risk,
        "summary": summary,
        "findings": {
            "company": company,
            "country": cc or None,
            "region_targeted": targeted,
            "region_source": ("explicit" if country else
                              "domain_cctld" if cc else "none"),
            "result_count": len(items),
            "scam_related_headlines": [it["title"] for it in scam_hits],
            "headlines": [f"{it['title']} ({it['source']}, {it['date']})"
                          for it in items[:8]],
        },
        "notes": notes,
    }
