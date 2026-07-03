"""Parse raw email headers for spoofing signals (offline, no key).

The full headers of a suspicious email are a goldmine: the real originating IP,
SPF/DKIM/DMARC authentication results, and From / Return-Path / Reply-To
mismatches that reveal spoofing or reply-hijacking.
"""

from __future__ import annotations

import email
import ipaddress
import re
from email.utils import parseaddr
from typing import Any

from ..common import RiskLevel

_IP_RE = re.compile(r"[\[(]?((?:\d{1,3}\.){3}\d{1,3}|[A-Fa-f0-9:]{4,})[\])]?")
_AUTH_RE = {
    "spf": re.compile(r"spf=(\w+)", re.IGNORECASE),
    "dkim": re.compile(r"dkim=(\w+)", re.IGNORECASE),
    "dmarc": re.compile(r"dmarc=(\w+)", re.IGNORECASE),
}


def _domain(addr: str) -> str:
    _, email_addr = parseaddr(addr or "")
    return email_addr.split("@")[-1].lower() if "@" in email_addr else ""


def _public_ips_from_received(received_headers: list[str]) -> list[str]:
    """Extract public (routable) IPs from Received: chain, outermost last."""
    ips: list[str] = []
    for hdr in received_headers:
        for m in _IP_RE.finditer(hdr):
            token = m.group(1)
            try:
                ip = ipaddress.ip_address(token)
            except ValueError:
                continue
            if ip.is_global and str(ip) not in ips:
                ips.append(str(ip))
    return ips


async def run(raw_headers: str) -> dict[str, Any]:
    """Analyze raw email headers for spoofing and extract the originating IP.

    Paste everything from the raw source (the Received:, From:, Return-Path:,
    Reply-To:, Authentication-Results: lines).
    """
    msg = email.message_from_string(raw_headers)

    from_addr = msg.get("From", "")
    return_path = msg.get("Return-Path", "")
    reply_to = msg.get("Reply-To", "")
    received = msg.get_all("Received", [])
    auth_results = " ".join(msg.get_all("Authentication-Results", [])
                            + msg.get_all("ARC-Authentication-Results", []))

    from_dom = _domain(from_addr)
    rp_dom = _domain(return_path)
    reply_dom = _domain(reply_to)

    auth: dict[str, str] = {}
    for name, rgx in _AUTH_RE.items():
        m = rgx.search(auth_results)
        if m:
            auth[name] = m.group(1).lower()

    origin_ips = _public_ips_from_received(received)

    red: list[str] = []
    yellow: list[str] = []

    if auth.get("spf") in ("fail", "softfail"):
        red.append(f"SPF {auth['spf']}")
    if auth.get("dkim") == "fail":
        red.append("DKIM fail")
    if auth.get("dmarc") == "fail":
        red.append("DMARC fail")
    if reply_dom and from_dom and reply_dom != from_dom:
        red.append(f"Reply-To domain ({reply_dom}) differs from From ({from_dom}) "
                   "— replies go elsewhere")
    if rp_dom and from_dom and rp_dom != from_dom:
        yellow.append(f"Return-Path ({rp_dom}) differs from From ({from_dom})")
    if not auth:
        yellow.append("No Authentication-Results header found — cannot verify SPF/DKIM/DMARC")

    if red:
        risk = RiskLevel.RED
        summary = "Spoofing indicators: " + "; ".join(red)
    elif yellow:
        risk = RiskLevel.YELLOW
        summary = "Suspicious: " + "; ".join(yellow)
    else:
        risk = RiskLevel.GREEN
        summary = "From/Return-Path/Reply-To consistent and authentication passed."

    notes = []
    if origin_ips:
        notes.append(f"Run check_ip on the originating IP(s): {', '.join(origin_ips)}")

    return {
        "check": "email_headers",
        "risk": risk,
        "summary": summary,
        "findings": {
            "from": from_addr or None,
            "from_domain": from_dom or None,
            "return_path_domain": rp_dom or None,
            "reply_to_domain": reply_dom or None,
            "spf": auth.get("spf"),
            "dkim": auth.get("dkim"),
            "dmarc": auth.get("dmarc"),
            "originating_ips": origin_ips,
            "red_flags": red,
            "yellow_flags": yellow,
        },
        "notes": notes,
    }
