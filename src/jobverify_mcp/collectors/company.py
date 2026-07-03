"""Company existence check via GLEIF + SEC EDGAR (both free, key-free).

GLEIF: open API over the global LEI database (entities with a Legal Entity
Identifier). SEC EDGAR: the list of US public-company filers (company_tickers,
cached locally). Both are positive-evidence sources — a match means the entity
is real; absence is weak evidence (many legit private/foreign firms are in
neither), not proof of a scam.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any

import httpx

from ..common import RiskLevel, handle_error, http_get_json
from .blocklists import _cache_dir, _is_stale

GLEIF_URL = "https://api.gleif.org/api/v1/lei-records"
SEC_TICKERS_URL = "https://www.sec.gov/files/company_tickers.json"
# SEC's fair-access policy requires a "Name Email" User-Agent (simple format only).
SEC_USER_AGENT = "jobverify-mcp research yessGlory17@users.noreply.github.com"

_SUFFIXES = re.compile(
    r"\b(inc|incorporated|corp|corporation|co|company|llc|ltd|limited|plc|"
    r"holdings|holding|group|sa|ag|nv|gmbh|as|the)\b", re.IGNORECASE)
_SEC: dict[str, Any] = {}


def _normalize(name: str) -> str:
    name = _SUFFIXES.sub(" ", name.lower())
    return re.sub(r"[^a-z0-9]+", " ", name).strip()


async def _ensure_sec() -> bool:
    path = _cache_dir() / "sec_company_tickers.json"
    if _is_stale(path):
        # SEC can 403 under bursty access; retry with small backoff.
        async with httpx.AsyncClient(follow_redirects=True) as client:
            for attempt in range(3):
                try:
                    r = await client.get(SEC_TICKERS_URL,
                                         headers={"User-Agent": SEC_USER_AGENT},
                                         timeout=40.0)
                    r.raise_for_status()
                    path.write_text(r.text)
                    break
                except Exception:  # noqa: BLE001
                    if attempt < 2:
                        await asyncio.sleep(1.5)
    return path.exists()


def _sec_match(name: str) -> list[str]:
    """Return SEC public-filer titles matching the (normalized) company name."""
    path = _cache_dir() / "sec_company_tickers.json"
    mtime = path.stat().st_mtime if path.exists() else 0.0
    if _SEC.get("mtime") != mtime:
        titles: list[tuple[str, str]] = []
        try:
            for row in json.loads(path.read_text()).values():
                title = row.get("title", "")
                titles.append((_normalize(title), title))
        except (OSError, json.JSONDecodeError):
            titles = []
        _SEC["titles"] = titles
        _SEC["mtime"] = mtime
    norm = _normalize(name)
    if len(norm) < 3:
        return []
    # Whole-word match to avoid substring false positives ("apple" vs "pineapple").
    pattern = re.compile(r"\b" + re.escape(norm) + r"\b")
    out = []
    for ntitle, title in _SEC["titles"]:
        if norm == ntitle or (len(norm) >= 4 and pattern.search(ntitle)):
            out.append(title)
    return out[:5]


async def run(name: str, jurisdiction: str | None = None) -> dict[str, Any]:
    """Search the global LEI database for a company by legal name.

    jurisdiction: optional ISO country code (e.g. 'US', 'GB', 'TR') to narrow
    results.
    """
    params: dict[str, Any] = {
        "filter[entity.legalName]": name,
        "page[size]": 10,
    }
    if jurisdiction:
        params["filter[entity.jurisdiction]"] = jurisdiction.upper()

    try:
        data = await http_get_json(GLEIF_URL, params=params)
    except Exception as e:
        return {
            "check": "company",
            "risk": RiskLevel.UNKNOWN,
            "summary": handle_error(e, "GLEIF"),
            "findings": {"name": name},
        }

    records = data.get("data", [])
    total = data.get("meta", {}).get("pagination", {}).get("total", len(records))

    # SEC EDGAR: is this a US public-company filer? (strong positive signal)
    sec_titles: list[str] = []
    if await _ensure_sec():
        sec_titles = _sec_match(name)

    caveat = ("GLEIF/SEC only list entities with an LEI or US public filing; many "
              "legit private/foreign firms are in neither, so absence isn't proof.")

    if not records:
        if sec_titles:
            return {
                "check": "company",
                "risk": RiskLevel.GREEN,
                "summary": (f"No LEI record, but '{name}' matches US SEC public "
                            f"filer(s): {', '.join(sec_titles)} — the entity is real."),
                "findings": {"name": name, "matches": 0,
                             "sec_public_filers": sec_titles},
                "notes": [caveat],
            }
        return {
            "check": "company",
            "risk": RiskLevel.YELLOW,
            "summary": (f"No LEI or SEC record found for '{name}'"
                        + (f" in {jurisdiction}" if jurisdiction else "")
                        + ". Weak signal — verify via the national trade registry."),
            "findings": {"name": name, "matches": 0, "sec_public_filers": []},
            "notes": [caveat,
                      "National registries: MERSIS (TR), Companies House (UK)."],
        }

    matches = []
    for rec in records[:5]:
        attr = rec.get("attributes", {})
        entity = attr.get("entity", {})
        reg = attr.get("registration", {})
        matches.append({
            "legal_name": entity.get("legalName", {}).get("name"),
            "lei": attr.get("lei"),
            "entity_status": entity.get("status"),            # ACTIVE / INACTIVE / NULL
            "registration_status": reg.get("status"),         # ISSUED / LAPSED / RETIRED
            "country": entity.get("legalAddress", {}).get("country"),
            "jurisdiction": entity.get("jurisdiction"),
            "registered_since": (reg.get("initialRegistrationDate") or "")[:10] or None,
        })

    active = [m for m in matches
              if (m.get("entity_status") == "ACTIVE"
                  and (m.get("registration_status") in ("ISSUED", "PENDING_TRANSFER",
                                                        "PENDING_ARCHIVAL", None)))]

    if active:
        risk = RiskLevel.GREEN
        summary = (f"Found {total} LEI record(s) for '{name}'; "
                   f"{len(active)} active — the entity appears real.")
    else:
        risk = RiskLevel.YELLOW
        summary = (f"Found {total} LEI record(s) for '{name}', but none are clearly "
                   "active (lapsed/retired) — verify the specific entity.")

    if sec_titles:
        summary += f" Also a US SEC public filer ({', '.join(sec_titles)})."

    return {
        "check": "company",
        "risk": risk,
        "summary": summary,
        "findings": {"name": name, "total_matches": total, "top_matches": matches,
                     "sec_public_filers": sec_titles},
        "notes": [caveat, "Confirm the specific legal entity, not just a name match."],
    }
