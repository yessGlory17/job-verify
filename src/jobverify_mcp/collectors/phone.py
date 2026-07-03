"""Phone number validation via Google's libphonenumber (offline, no API key)."""

from __future__ import annotations

from typing import Any

import phonenumbers
from phonenumbers import PhoneNumberType, carrier, geocoder, timezone

from ..common import RiskLevel

_TYPE_NAMES = {
    PhoneNumberType.FIXED_LINE: "fixed line",
    PhoneNumberType.MOBILE: "mobile",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed line or mobile",
    PhoneNumberType.TOLL_FREE: "toll free",
    PhoneNumberType.PREMIUM_RATE: "premium rate",
    PhoneNumberType.SHARED_COST: "shared cost",
    PhoneNumberType.VOIP: "VoIP",
    PhoneNumberType.PERSONAL_NUMBER: "personal number",
    PhoneNumberType.PAGER: "pager",
    PhoneNumberType.UAN: "UAN",
    PhoneNumberType.VOICEMAIL: "voicemail",
    PhoneNumberType.UNKNOWN: "unknown",
}


async def run(phone: str, default_region: str | None = None) -> dict[str, Any]:
    """Validate and describe a phone number.

    VoIP / premium-rate / invalid numbers are common in recruiter scams.
    """
    try:
        parsed = phonenumbers.parse(phone, default_region)
    except phonenumbers.NumberParseException as e:
        return {
            "check": "phone",
            "risk": RiskLevel.YELLOW,
            "summary": f"Could not parse '{phone}': {e}. "
                       "If no country code, pass default_region (e.g. 'US', 'TR').",
            "findings": {"input": phone},
        }

    is_valid = phonenumbers.is_valid_number(parsed)
    is_possible = phonenumbers.is_possible_number(parsed)
    num_type = phonenumbers.number_type(parsed)
    type_name = _TYPE_NAMES.get(num_type, "unknown")
    region = phonenumbers.region_code_for_number(parsed)
    location = geocoder.description_for_number(parsed, "en")
    carrier_name = carrier.name_for_number(parsed, "en")
    tzs = timezone.time_zones_for_number(parsed)
    e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)

    notes: list[str] = []
    if not is_valid:
        risk = RiskLevel.RED
        summary = "Number is NOT valid — a common sign of a fake contact."
    elif num_type in (PhoneNumberType.VOIP, PhoneNumberType.PREMIUM_RATE,
                      PhoneNumberType.PERSONAL_NUMBER):
        risk = RiskLevel.YELLOW
        summary = f"Valid but {type_name} — VoIP/premium numbers are often disposable."
    else:
        risk = RiskLevel.GREEN
        summary = f"Valid {type_name} number in {location or region or 'unknown'}."

    if not carrier_name and is_valid:
        notes.append("No carrier data (typical for fixed lines / VoIP).")

    return {
        "check": "phone",
        "risk": risk,
        "summary": summary,
        "findings": {
            "e164": e164,
            "valid": is_valid,
            "possible": is_possible,
            "type": type_name,
            "region": region,
            "location": location,
            "carrier": carrier_name or None,
            "timezones": ", ".join(tzs) if tzs else None,
        },
        "notes": notes,
    }
