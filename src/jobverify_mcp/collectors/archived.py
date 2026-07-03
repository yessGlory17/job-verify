"""Fetch the text of an archived web page from the Internet Archive (no key).

This is the LEGAL way to read a LinkedIn profile / company page: we fetch the
snapshot stored by web.archive.org, not LinkedIn itself. Useful to evaluate a
recruiter's archived headline/company or a company page's about text, and — via
the snapshot date — a lower bound on how long the page has existed.
"""

from __future__ import annotations

import html
import re
from datetime import datetime, timezone
from typing import Any

import httpx

from ..common import RiskLevel, USER_AGENT, handle_error

AVAILABLE_API = "https://archive.org/wayback/available"
REQ_TIMEOUT = 25.0
MAX_TEXT = 4000

_TAG_RE = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL)
_ANY_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"[ \t\r\f\v]+")
_NL_RE = re.compile(r"\n\s*\n\s*\n+")


def _html_to_text(raw: str) -> str:
    raw = _TAG_RE.sub(" ", raw)
    raw = re.sub(r"<br\s*/?>", "\n", raw, flags=re.IGNORECASE)
    raw = re.sub(r"</(p|div|li|h[1-6]|tr)>", "\n", raw, flags=re.IGNORECASE)
    text = _ANY_TAG_RE.sub("", raw)
    text = html.unescape(text)
    text = _WS_RE.sub(" ", text)
    text = _NL_RE.sub("\n\n", text)
    return text.strip()


async def run(url: str, when: str | None = None) -> dict[str, Any]:
    """Fetch the archived text of a URL.

    when: optional 8-14 digit timestamp (YYYYMMDD...) to target a snapshot near a
    date; defaults to the most recent snapshot.
    """
    url = url.strip()
    target = when or datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    last_err: Exception | None = None
    snap = None
    text = ""
    snap_url = ts = ""
    # The Internet Archive can be transiently slow; retry once.
    for attempt in range(2):
        try:
            async with httpx.AsyncClient(follow_redirects=True) as client:
                avail = await client.get(AVAILABLE_API,
                                         params={"url": url, "timestamp": target},
                                         headers={"User-Agent": USER_AGENT},
                                         timeout=REQ_TIMEOUT)
                avail.raise_for_status()
                snap = (avail.json().get("archived_snapshots") or {}).get("closest")
                if not snap:
                    return {
                        "check": "archived_page",
                        "risk": RiskLevel.YELLOW,
                        "summary": ("No Internet Archive snapshot for this URL — it "
                                    "may be new, private, or never indexed."),
                        "findings": {"url": url, "snapshot": None},
                    }
                snap_url = snap.get("url")
                ts = snap.get("timestamp", "")
                page = await client.get(snap_url,
                                        headers={"User-Agent": USER_AGENT},
                                        timeout=REQ_TIMEOUT)
                page.raise_for_status()
                text = _html_to_text(page.text)
                last_err = None
                break
        except Exception as e:  # noqa: BLE001 - retry then report
            last_err = e
    if last_err is not None:
        return {
            "check": "archived_page",
            "risk": RiskLevel.UNKNOWN,
            "summary": handle_error(last_err, "archived_page"),
            "findings": {"url": url},
        }

    snap_date = None
    if len(ts) >= 8:
        snap_date = f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}"

    truncated = len(text) > MAX_TEXT
    excerpt = text[:MAX_TEXT] + ("…" if truncated else "")

    return {
        "check": "archived_page",
        "risk": RiskLevel.UNKNOWN,  # content is evidence; the agent judges it
        "summary": (f"Archived snapshot from {snap_date} "
                    f"({len(text)} chars extracted). Evaluate the content below."),
        "findings": {
            "url": url,
            "snapshot_url": snap_url,
            "snapshot_date": snap_date,
            "text_excerpt": excerpt,
            "truncated": truncated,
        },
        "notes": ["This is Internet Archive content, not a live LinkedIn fetch. "
                  "Older/less-detailed than the live page; treat as supporting evidence."],
    }
