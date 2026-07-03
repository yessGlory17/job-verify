"""Shared utilities: HTTP client, error handling, response formatting."""

from __future__ import annotations

import json
import re
from enum import Enum
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

from .config import HTTP_TIMEOUT, USER_AGENT


class ResponseFormat(str, Enum):
    """Output format for tool responses."""

    MARKDOWN = "markdown"
    JSON = "json"


class RiskLevel(str, Enum):
    """Coarse risk signal a collector emits for a single check."""

    RED = "red"          # strong scam indicator
    YELLOW = "yellow"    # suspicious / needs attention
    GREEN = "green"      # looks legitimate for this check
    UNKNOWN = "unknown"  # could not determine (e.g. missing key, no data)


async def http_get_json(url: str, *, params: dict | None = None,
                        headers: dict | None = None) -> Any:
    """GET a URL and parse JSON. Raises httpx errors to the caller."""
    merged_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        merged_headers.update(headers)
    async with httpx.AsyncClient(follow_redirects=True) as client:
        resp = await client.get(url, params=params, headers=merged_headers,
                                timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        return resp.json()


# --------------------------------------------------------------------------- #
# Domain / host normalization (shared by the domain-oriented collectors)
# --------------------------------------------------------------------------- #
def domain_from_input(value: str) -> str:
    """Accept a bare domain, an email, or a URL and return the bare hostname.

    e.g. 'hr@acme.com', 'https://www.acme.com/jobs', 'acme.com.' -> 'acme.com'.
    """
    value = value.strip().lower()
    if "@" in value:
        value = value.split("@")[-1]
    value = re.sub(r"^https?://", "", value).split("/")[0]
    return re.sub(r"^www\.", "", value).rstrip(".")


def split_domain(domain: str) -> tuple[str, str]:
    """Split a bare domain into (second-level label, tld).

    'stripe.com' -> ('stripe', 'com'); a single label -> (label, '').
    """
    labels = domain.split(".")
    if len(labels) >= 2:
        return labels[-2], labels[-1]
    return domain, ""


def registrable(host: str) -> str:
    """Normalize a host/URL and return its registrable domain (last two labels).

    'https://sub.stripe.com/x' -> 'stripe.com'; a single label is returned as-is.
    """
    core, tld = split_domain(domain_from_input(host or ""))
    return f"{core}.{tld}" if tld else core


def domain_core(host: str) -> str:
    """The brand core (second-level label) of a host/URL, e.g. stripe.com -> 'stripe'."""
    return split_domain(registrable(host))[0]


async def resolve_records(name: str, rtype: str, *, lifetime: float = 8.0,
                          resolver: "dns.asyncresolver.Resolver | None" = None) -> list:
    """Async-resolve DNS records, returning a list of rdata (empty on any failure).

    Pass a shared `resolver` when issuing many concurrent queries (its `lifetime`
    is then assumed already set); otherwise a per-call resolver is created.
    """
    r = resolver or dns.asyncresolver.Resolver()
    if resolver is None:
        r.lifetime = lifetime
    try:
        return list(await r.resolve(name, rtype))
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        return []


def handle_error(e: Exception, context: str = "") -> str:
    """Consistent, actionable error strings across collectors."""
    prefix = f"[{context}] " if context else ""
    if isinstance(e, httpx.HTTPStatusError):
        code = e.response.status_code
        if code == 404:
            return f"{prefix}Not found (404). The identifier may not exist."
        if code in (401, 403):
            return (f"{prefix}Access denied or rate-limited ({code}). This source "
                    "needs no API key; it may be throttling — retry later.")
        if code == 429:
            return f"{prefix}Rate limit exceeded (429). Wait before retrying."
        return f"{prefix}API request failed with status {code}."
    if isinstance(e, httpx.TimeoutException):
        return f"{prefix}Request timed out. The service may be slow or down."
    if isinstance(e, httpx.RequestError):
        return f"{prefix}Network error: {type(e).__name__}."
    return f"{prefix}Unexpected error: {type(e).__name__}: {e}"


def render(result: dict[str, Any], fmt: ResponseFormat) -> str:
    """Render a collector result dict as JSON or a compact Markdown block.

    Every collector returns a dict shaped roughly as:
        {
          "check": str,          # name of the check
          "risk": RiskLevel,     # coarse signal
          "summary": str,        # one-line human summary
          "findings": {...},     # arbitrary detail fields
          "notes": [str, ...]    # optional caveats
        }
    """
    if fmt == ResponseFormat.JSON:
        return json.dumps(result, indent=2, default=str, ensure_ascii=False)

    risk = result.get("risk", RiskLevel.UNKNOWN)
    risk_str = risk.value if isinstance(risk, RiskLevel) else str(risk)
    icon = {"red": "🔴", "yellow": "🟡", "green": "🟢"}.get(risk_str, "⚪")

    lines = [f"### {result.get('check', 'check')} — {icon} {risk_str.upper()}"]
    if result.get("summary"):
        lines.append(result["summary"])
    findings = result.get("findings") or {}
    if findings:
        lines.append("")
        for k, v in findings.items():
            if v is None or v == "" or v == [] or v == {}:
                continue
            if isinstance(v, list):
                v = ", ".join(str(x) for x in v)
            lines.append(f"- **{k}**: {v}")
    for note in result.get("notes") or []:
        lines.append(f"> {note}")
    return "\n".join(lines)
