"""Detect known recruiter/job-scam tactics (TTPs) in message text (offline, no key).

Encodes the 2026 recruiter-scam playbook documented by the FTC, Indeed, McAfee
and Bitdefender. Deterministic keyword/regex matching complements the agent's own
judgment with reproducible hits. English + some Turkish patterns.
"""

from __future__ import annotations

import re
from typing import Any

from ..common import RiskLevel

# category -> (severity, human label, regex)
_PATTERNS: dict[str, tuple[str, str, re.Pattern]] = {
    "advance_fee": ("high", "Up-front fee requested (real recruiters never charge)",
                    re.compile(r"\b(processing|registration|placement|training|"
                               r"background[- ]?check|application|activation)\s+fee\b"
                               r"|\bpay(ment)?\b.{0,20}\bfee\b|\bupfront\b|\bpe[sş]in\b"
                               r"|\bücret\s+yat[ıi]r", re.IGNORECASE)),
    "fake_check": ("high", "Fake check / overpayment / send-money-back scheme",
                   re.compile(r"\b(deposit|cash)\s+the\s+check\b|\boverpay"
                              r"|\bsend\s+(back|the\s+difference)\b|\bwire\s+the\b"
                              r"|\bmoney\s+order\b", re.IGNORECASE)),
    "equipment_purchase": ("high", "Buy your own equipment (with 'reimbursement')",
                           re.compile(r"\b(purchase|buy)\b.{0,30}\b(laptop|equipment|"
                                      r"computer|software|gift\s?card)\b"
                                      r"|\breimburse", re.IGNORECASE)),
    "task_scam": ("high", "Task/commission scam (deposit to earn / app tasks)",
                  re.compile(r"\bcomplete\s+tasks?\b|\b(app|online)\s+tasks?\b"
                             r"|\bcommission\b|\brecharge\b|\bdeposit\b.{0,20}\b(unlock|"
                             r"earn|withdraw)\b|\boptimi[sz]e\s+(products|reviews)\b",
                             re.IGNORECASE)),
    "reshipping": ("high", "Reshipping / package-forwarding (money-mule) scheme",
                   re.compile(r"\bres?hip(ping)?\b|\bforward\s+packages?\b"
                              r"|\breceive\s+(and\s+)?(re)?ship\b|\bpackage\s+handler\b",
                              re.IGNORECASE)),
    "crypto_payment": ("high", "Crypto payment involved",
                       re.compile(r"\b(bitcoin|btc|ethereum|eth|usdt|tether|crypto"
                                  r"|binance|trc-?20|erc-?20|wallet\s+address)\b",
                                  re.IGNORECASE)),
    "personal_docs_early": ("medium", "Sensitive personal docs requested early",
                            re.compile(r"\b(social\s+security|ssn|passport|bank\s+"
                                       r"statement|driver'?s?\s+licen[cs]e|national\s+id"
                                       r"|credit\s+card|kimlik|tc\s?kimlik)\b",
                                       re.IGNORECASE)),
    "off_platform": ("medium", "Push to move off-platform (WhatsApp/Telegram)",
                     re.compile(r"\b(whats\s?app|telegram|signal|wechat|skype"
                                r"|t\.me/|wa\.me/)\b", re.IGNORECASE)),
    "urgency": ("low", "Urgency / pressure",
                re.compile(r"\b(act\s+now|urgent(ly)?|immediately|right\s+away"
                           r"|limited\s+(slots|spots|time)|today\s+only|asap|acele"
                           r"|hemen)\b", re.IGNORECASE)),
    "no_interview": ("medium", "Offer without a real interview",
                     re.compile(r"\b(no\s+interview|without\s+(an?\s+)?interview"
                                r"|hired\s+immediately|start\s+(work\s+)?immediately"
                                r"|instant\s+(hire|offer)|m[üu]lakats[ıi]z)\b",
                                re.IGNORECASE)),
    "too_good_pay": ("medium", "Unrealistic pay for minimal work",
                     re.compile(r"\$\s?\d{3,}(?:[.,]\d+)?\s*(?:/|per\s+)?(day|hour|hr)"
                                r"|\bearn\b.{0,20}\b(daily|per\s+day|from\s+home)\b",
                                re.IGNORECASE)),
}

_SEV_WEIGHT = {"high": 3, "medium": 2, "low": 1}


async def run(text: str) -> dict[str, Any]:
    """Scan message text for known job-scam tactics and score them."""
    matched: list[dict[str, str]] = []
    score = 0
    for cat, (severity, label, rgx) in _PATTERNS.items():
        m = rgx.search(text)
        if m:
            matched.append({"tactic": cat, "severity": severity, "label": label,
                            "evidence": m.group(0)})
            score += _SEV_WEIGHT[severity]

    highs = [x for x in matched if x["severity"] == "high"]
    if highs or score >= 5:
        risk = RiskLevel.RED
        summary = (f"{len(matched)} scam tactic(s) detected including "
                   f"{len(highs)} high-severity — strong scam pattern.")
    elif matched:
        risk = RiskLevel.YELLOW
        summary = f"{len(matched)} suspicious tactic(s) detected — treat with caution."
    else:
        risk = RiskLevel.GREEN
        summary = "No known job-scam tactic keywords detected in the text."

    return {
        "check": "scam_patterns",
        "risk": risk,
        "summary": summary,
        "findings": {
            "score": score,
            "tactics": [x["tactic"] for x in matched],
            "detail": matched,
        },
        "notes": ["Keyword-based; absence of hits is not proof of safety. "
                  "Real recruiters never ask you to pay to get a job."],
    }
