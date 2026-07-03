"""Verify a physical address via OpenStreetMap Nominatim (free, no key).

A fake company often lists an address that doesn't exist, or resolves to a
residential house / random spot rather than an office. Nominatim geocodes the
address and tells us whether it resolves and what kind of place it is.

Nominatim usage policy: descriptive User-Agent required, max ~1 request/second.
"""

from __future__ import annotations

from typing import Any

import httpx

from ..common import RiskLevel, handle_error

NOMINATIM_URL = "https://nominatim.openstreetmap.org/search"
# Nominatim requires a UA that identifies the application (URL/contact form).
NOMINATIM_UA = "jobverify-mcp/0.1 (+https://github.com/yessGlory17/job-verify)"
REQ_TIMEOUT = 20.0

# OSM place types that are plausible for a real business location.
_BUSINESSY = {"commercial", "industrial", "office", "retail", "building",
              "yes", "public", "civic", "university", "commercial_building"}
_RESIDENTIAL = {"residential", "house", "apartments", "detached", "terrace",
                "dormitory"}


async def run(address: str) -> dict[str, Any]:
    """Geocode an address and assess whether it plausibly hosts a business."""
    address = address.strip()
    if len(address) < 5:
        return {
            "check": "address",
            "risk": RiskLevel.YELLOW,
            "summary": "Address too short to verify.",
            "findings": {"input": address},
        }

    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            resp = await client.get(
                NOMINATIM_URL,
                params={"q": address, "format": "json", "addressdetails": 1,
                        "extratags": 1, "limit": 3},
                headers={"User-Agent": NOMINATIM_UA},
                timeout=REQ_TIMEOUT)
            resp.raise_for_status()
            results = resp.json()
    except Exception as e:  # noqa: BLE001
        return {
            "check": "address",
            "risk": RiskLevel.UNKNOWN,
            "summary": handle_error(e, "address"),
            "findings": {"address": address},
        }

    if not results:
        return {
            "check": "address",
            "risk": RiskLevel.YELLOW,
            "summary": ("Address did not resolve on OpenStreetMap. It may be "
                        "incomplete, fabricated, or simply unmapped — verify manually."),
            "findings": {"address": address, "resolved": False},
        }

    top = results[0]
    place_type = (top.get("type") or "").lower()
    place_class = (top.get("class") or "").lower()
    display = top.get("display_name")

    is_residential = place_type in _RESIDENTIAL or place_class == "residential"
    is_business = (place_class in {"office", "shop", "commercial", "building"}
                   or place_type in _BUSINESSY)

    if is_residential and not is_business:
        risk = RiskLevel.YELLOW
        summary = ("Address resolves to a residential location — unusual for a company "
                   "HQ (could be a home office, a mail drop, or fabricated).")
    elif is_business:
        risk = RiskLevel.GREEN
        summary = (f"Address resolves to a business/commercial location "
                   f"({place_class}/{place_type}) — plausible.")
    else:
        risk = RiskLevel.GREEN
        summary = f"Address resolves ({place_class}/{place_type}). Cross-check it matches the company."

    return {
        "check": "address",
        "risk": risk,
        "summary": summary,
        "findings": {
            "address": address,
            "resolved": True,
            "osm_class": place_class,
            "osm_type": place_type,
            "matched_location": display,
            "lat": top.get("lat"),
            "lon": top.get("lon"),
        },
        "notes": ["Nominatim can't detect virtual-office / mail-forwarding services; "
                  "if many companies share the address, treat it as a red flag."],
    }
