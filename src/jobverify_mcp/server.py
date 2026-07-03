#!/usr/bin/env python3
"""MCP server for LinkedIn recruiter / job-offer scam detection.

Exposes free OSINT collectors as tools. The calling LLM (e.g. Claude) is the
agent: it decides which tools to run on the data a user pastes, then combines
the signals into a verdict. Use the `analyze` prompt for guidance.
"""

from __future__ import annotations

from typing import Optional

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field

from .collectors import address as address_col
from .collectors import archived as archived_col
from .collectors import certtrans as certtrans_col
from .collectors import company as company_col
from .collectors import crypto as crypto_col
from .collectors import domain as domain_col
from .collectors import github_org as github_org_col
from .collectors import domain_auth as domain_auth_col
from .collectors import email as email_col
from .collectors import email_footprint as email_footprint_col
from .collectors import email_headers as email_headers_col
from .collectors import entities as entities_col
from .collectors import ip as ip_col
from .collectors import lookalike as lookalike_col
from .collectors import news as news_col
from .collectors import phone as phone_col
from .collectors import scam_patterns as scam_patterns_col
from .collectors import typosquat as typosquat_col
from .collectors import url_check as url_col
from .collectors import username as username_col
from .collectors import wayback as wayback_col
from .common import ResponseFormat, render

mcp = FastMCP("jobverify_mcp")

_READONLY = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": True,
}


# --------------------------------------------------------------------------- #
# Input models
# --------------------------------------------------------------------------- #
class _Base(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="'markdown' (human-readable) or 'json' (structured).",
    )


class EmailInput(_Base):
    email: str = Field(..., description="Email address to assess, e.g. 'hr@acme-jobs.com'")
    company_domain: Optional[str] = Field(
        default=None,
        description="If the sender claims a company, its real domain (e.g. 'acme.com') "
                    "to check the email matches it.")


class DomainInput(_Base):
    domain: str = Field(..., description="Domain, URL, or email to look up (e.g. 'acme.com', "
                                        "'https://acme.com/jobs', 'hr@acme.com').")


class IpInput(_Base):
    ip: str = Field(..., description="IPv4/IPv6 address to check, e.g. '203.0.113.5'.")


class PhoneInput(_Base):
    phone: str = Field(..., description="Phone number, ideally E.164 like '+14155552671'.")
    default_region: Optional[str] = Field(
        default=None,
        description="ISO country code (e.g. 'US', 'TR') if the number has no '+' prefix.")


class UrlInput(_Base):
    url: str = Field(..., description="URL or domain to check against phishing/malware feeds.")


class WaybackInput(_Base):
    url: str = Field(..., description="URL to check in the Internet Archive, e.g. a LinkedIn "
                                     "profile 'https://www.linkedin.com/in/someone'.")


class ArchivedPageInput(_Base):
    url: str = Field(..., description="URL whose archived text to fetch (e.g. a LinkedIn "
                                     "profile or company page).")
    when: Optional[str] = Field(
        default=None,
        description="Optional YYYYMMDD timestamp to target a snapshot near a date; "
                    "defaults to the most recent snapshot.")


class CompanyInput(_Base):
    name: str = Field(..., description="Company name to search in official registries.")
    jurisdiction: Optional[str] = Field(
        default=None,
        description="Optional ISO country code to narrow search (e.g. 'US', 'GB', 'TR').")


class EntitiesInput(_Base):
    text: str = Field(..., description="Raw recruiter message / job offer to parse.")
    default_region: Optional[str] = Field(
        default=None,
        description="ISO code (e.g. 'TR', 'US') to catch local phone numbers without '+'.")


class EmailHeadersInput(_Base):
    raw_headers: str = Field(..., description="Full raw email headers pasted from the "
                                             "message source (Received, From, Reply-To, "
                                             "Authentication-Results, etc.).")


class DomainAuthInput(_Base):
    domain: str = Field(..., description="Domain / email / URL whose SPF+DMARC to check.")


class TyposquatInput(_Base):
    domain: str = Field(..., description="Domain to test for lookalike/typosquatting.")
    brand: Optional[str] = Field(
        default=None,
        description="Optional claimed company name to compare against directly.")


class CryptoInput(_Base):
    address: str = Field(..., description="BTC or EVM (0x…) crypto address to check.")


class ScamPatternsInput(_Base):
    text: str = Field(..., description="Raw recruiter message / job offer text to scan.")


class CertTransInput(_Base):
    domain: str = Field(..., description="Domain to look up in Certificate Transparency logs.")


class LookalikeInput(_Base):
    domain: str = Field(..., description="Real brand domain to find live look-alikes of "
                                        "(e.g. 'stripe.com').")
    max_checks: int = Field(default=300, ge=10, le=600,
                            description="Cap on permutations to DNS-resolve.")


class EmailFootprintInput(_Base):
    email: str = Field(..., description="Email address to look up (Gravatar footprint).")


class UsernameInput(_Base):
    username: str = Field(..., description="Username/handle to check across platforms.")


class NewsInput(_Base):
    company: str = Field(..., description="Company name to search news for.")
    country: Optional[str] = Field(
        default=None,
        description="The company's ACTUAL ISO-2 country (e.g. 'TR', 'DE'), determined "
                    "from its address/website/registry — NOT a default. Omit only if "
                    "genuinely unknown; then pass company_domain instead.")
    language: Optional[str] = Field(
        default=None, description="ISO-2 language code (e.g. 'tr', 'en'); inferred from "
                                  "country if omitted.")
    company_domain: Optional[str] = Field(
        default=None,
        description="The company's website/email domain (e.g. 'acme.com.tr'). Used to "
                    "infer the region from its ccTLD when country is not given.")


class AddressInput(_Base):
    address: str = Field(..., description="Physical address to geocode/verify.")


class GithubOrgInput(_Base):
    org_or_name: str = Field(..., description="GitHub org handle (e.g. 'stripe') or "
                                             "a company name to search for.")
    expected_domain: Optional[str] = Field(
        default=None,
        description="The company's real domain, to confirm the org website matches.")


# --------------------------------------------------------------------------- #
# Tools
# --------------------------------------------------------------------------- #
@mcp.tool(name="check_email", annotations={"title": "Check Email", **_READONLY})
async def check_email(params: EmailInput) -> str:
    """Assess a recruiter's email: disposable domain, free provider, MX records,
    and (if given) whether it matches the claimed company's domain.

    Use when: you have the sender's email address.
    Returns a risk-scored result (red/yellow/green) with findings.
    """
    result = await email_col.run(params.email, params.company_domain)
    return render(result, params.response_format)


@mcp.tool(name="check_domain", annotations={"title": "Check Domain Registration", **_READONLY})
async def check_domain(params: DomainInput) -> str:
    """Look up domain registration via RDAP and assess its age. Freshly
    registered domains posing as established companies are a strong scam signal.

    Use when: you have a company website, job-portal link, or email domain.
    """
    result = await domain_col.run(params.domain)
    return render(result, params.response_format)


@mcp.tool(name="check_ip", annotations={"title": "Check IP Reputation", **_READONLY})
async def check_ip(params: IpInput) -> str:
    """Check an IP against local blocklists (FireHOL abuse aggregate + Tor exit
    list) and identify its ASN/org/country (iptoasn) with a hosting/datacenter
    heuristic. No API key. Blocklisted or datacenter IPs are red flags.

    Use when: you have an originating IP (e.g. from email headers).
    """
    result = await ip_col.run(params.ip)
    return render(result, params.response_format)


@mcp.tool(name="check_phone", annotations={"title": "Validate Phone Number", **_READONLY})
async def check_phone(params: PhoneInput) -> str:
    """Validate a phone number (offline, libphonenumber): validity, type
    (mobile/VoIP/premium), region, carrier. VoIP/invalid numbers are red flags.

    Use when: a recruiter gives a phone/WhatsApp number.
    """
    result = await phone_col.run(params.phone, params.default_region)
    return render(result, params.response_format)


@mcp.tool(name="check_url", annotations={"title": "Check URL Safety", **_READONLY})
async def check_url(params: UrlInput) -> str:
    """Check a URL/domain against local phishing + malware blocklists — no API
    key. Uses Phishing.Database (~390k phishing domains) and the URLhaus recent
    feed (malware URLs). Any hit means high risk.

    Use when: the offer contains a link (application portal, form, download).
    """
    result = await url_col.run(params.url)
    return render(result, params.response_format)


@mcp.tool(name="check_wayback", annotations={"title": "Check Archive History", **_READONLY})
async def check_wayback(params: WaybackInput) -> str:
    """Check the Internet Archive history of a URL (e.g. a LinkedIn profile or
    company site). A missing or very recent first snapshot suggests a new page.
    This is the legal proxy for 'account age' since LinkedIn hides creation dates.

    Use when: you have a profile/company URL and want an age lower-bound.
    """
    result = await wayback_col.run(params.url)
    return render(result, params.response_format)


@mcp.tool(name="fetch_archived_page", annotations={"title": "Fetch Archived Page", **_READONLY})
async def fetch_archived_page(params: ArchivedPageInput) -> str:
    """Fetch the archived TEXT of a page from the Internet Archive (no key). This
    is the legal way to read a LinkedIn profile/company page — it reads the
    web.archive.org snapshot, NOT LinkedIn live. Returns the extracted text plus
    the snapshot date so you can evaluate the recruiter's headline/company or a
    company page's about text.

    Use when: you have a LinkedIn (or company) URL and want to evaluate its content.
    """
    result = await archived_col.run(params.url, params.when)
    return render(result, params.response_format)


@mcp.tool(name="verify_company", annotations={"title": "Verify Company", **_READONLY})
async def verify_company(params: CompanyInput) -> str:
    """Search the global LEI database (GLEIF, no API key) for a company name.
    A match with ACTIVE status is strong evidence the entity is real. Note that
    only entities with an LEI are listed, so 'no match' is weak evidence.

    Use when: a company name is claimed in the offer.
    """
    result = await company_col.run(params.name, params.jurisdiction)
    return render(result, params.response_format)


@mcp.tool(name="check_crypto_address", annotations={"title": "Check Crypto Address", **_READONLY})
async def check_crypto_address(params: CryptoInput) -> str:
    """Check a BTC/EVM crypto address against open scam databases (no key). Any
    request to pay or receive crypto for a job is itself a major red flag; a
    listed address is a strong fraud signal.

    Use when: extract_entities found a crypto address in the message.
    """
    result = await crypto_col.run(params.address)
    return render(result, params.response_format)


@mcp.tool(name="check_scam_patterns", annotations={"title": "Check Scam Patterns", **_READONLY})
async def check_scam_patterns(params: ScamPatternsInput) -> str:
    """Scan message text for known recruiter/job-scam tactics (offline, no key):
    advance fee, fake check, equipment purchase, task scam, reshipping, crypto
    payment, personal-docs-early, off-platform push, urgency, no-interview offer.

    Use when: you have the raw offer text and want deterministic TTP hits.
    """
    result = await scam_patterns_col.run(params.text)
    return render(result, params.response_format)


@mcp.tool(name="check_certificate_transparency",
          annotations={"title": "Check Certificate Transparency", **_READONLY})
async def check_certificate_transparency(params: CertTransInput) -> str:
    """Look up a domain's SSL certificate history via crt.sh (no key). A cert
    first seen only days ago = fresh phishing infrastructure; a long history and
    many subdomains = established. Complements check_domain (RDAP age).

    Use when: you have a company/link domain and want infra age corroboration.
    """
    result = await certtrans_col.run(params.domain)
    return render(result, params.response_format)


@mcp.tool(name="find_lookalike_domains", annotations={"title": "Find Lookalike Domains", **_READONLY})
async def find_lookalike_domains(params: LookalikeInput) -> str:
    """Generate typo/homoglyph/TLD permutations of a REAL brand domain and return
    the ones that actually resolve in DNS (no key). Live look-alikes are prime
    fake-recruiter / phishing infrastructure.

    Use when: you know the real company domain and want to hunt impersonators.
    """
    result = await lookalike_col.run(params.domain, params.max_checks)
    return render(result, params.response_format)


@mcp.tool(name="check_email_footprint", annotations={"title": "Check Email Footprint", **_READONLY})
async def check_email_footprint(params: EmailFootprintInput) -> str:
    """Check an email's public Gravatar profile & linked social accounts (no key).
    An established identity is a mild legitimacy signal; a throwaway scam address
    usually has none. Corroborate the linked accounts against the recruiter.

    Use when: you want a quick digital-footprint read on a sender's email.
    """
    result = await email_footprint_col.run(params.email)
    return render(result, params.response_format)


@mcp.tool(name="check_username", annotations={"title": "Check Username", **_READONLY})
async def check_username(params: UsernameInput) -> str:
    """Check a username/handle across GitHub, Reddit and Keybase (no key). Reveals
    online history and (via GitHub) account age. A handle that exists nowhere is a
    sock-puppet signal. For broader coverage, also web-search the username.

    Use when: you have a recruiter's handle/username to vet.
    """
    result = await username_col.run(params.username)
    return render(result, params.response_format)


@mcp.tool(name="search_company_news", annotations={"title": "Search Company News", **_READONLY})
async def search_company_news(params: NewsInput) -> str:
    """Search regional/local news for a company via Google News RSS (no key).
    Especially useful for SMALL companies that GLEIF/SEC don't cover: a real firm
    usually has some press footprint in its region, and any headline flagging it
    as a scam/fraud is decisive.

    IMPORTANT: determine the company's ACTUAL country FIRST (from its stated HQ
    address, its website's ccTLD, its GLEIF jurisdiction, or a web search) and
    pass it as `country` (or pass `company_domain` to infer it). Do NOT rely on a
    default region — searching the wrong country hides real local coverage and a
    "no news" result then means nothing.

    Use when: verifying a small/local company beyond registries.
    """
    result = await news_col.run(params.company, params.country, params.language,
                                params.company_domain)
    return render(result, params.response_format)


@mcp.tool(name="verify_address", annotations={"title": "Verify Address", **_READONLY})
async def verify_address(params: AddressInput) -> str:
    """Geocode a physical address via OpenStreetMap (no key) and assess whether it
    resolves and is a business vs residential location. A company 'HQ' that does
    not resolve, or resolves to a house, is a red flag.

    Use when: an offer lists a company address to verify.
    """
    result = await address_col.run(params.address)
    return render(result, params.response_format)


@mcp.tool(name="check_github_org", annotations={"title": "Check GitHub Org", **_READONLY})
async def check_github_org(params: GithubOrgInput) -> str:
    """Verify a company's GitHub organization (no key): whether it exists, its age,
    repo count, and whether its website matches the company domain. A real tech
    company usually has a GitHub org linking back to its site; a scam rarely does.

    Use when: the company claims to build software/tech.
    """
    result = await github_org_col.run(params.org_or_name, params.expected_domain)
    return render(result, params.response_format)


@mcp.tool(name="extract_entities", annotations={"title": "Extract Entities", **_READONLY})
async def extract_entities(params: EntitiesInput) -> str:
    """Parse a raw recruiter message into structured entities (offline, no key):
    emails, domains, URLs, LinkedIn URLs, phone numbers, IPs, crypto addresses,
    and off-platform (WhatsApp/Telegram) mentions. Run this FIRST, then feed each
    entity to the specific check_* tools so nothing is missed.

    Use when: you have a raw message/offer and want the entities to investigate.
    """
    result = await entities_col.run(params.text, params.default_region)
    return render(result, params.response_format)


@mcp.tool(name="parse_email_headers", annotations={"title": "Parse Email Headers", **_READONLY})
async def parse_email_headers(params: EmailHeadersInput) -> str:
    """Analyze raw email headers for spoofing (offline, no key): SPF/DKIM/DMARC
    results, From vs Return-Path vs Reply-To mismatches (reply-hijacking), and the
    real originating IP (feed it to check_ip).

    Use when: the user can paste the full raw headers of a suspicious email.
    """
    result = await email_headers_col.run(params.raw_headers)
    return render(result, params.response_format)


@mcp.tool(name="check_domain_auth", annotations={"title": "Check Domain Email Auth", **_READONLY})
async def check_domain_auth(params: DomainAuthInput) -> str:
    """Check a domain's SPF and DMARC DNS records (no key). A domain with no SPF
    and weak/absent DMARC (p=none) is trivially spoofable — so a 'recruiter'
    email from it is easy to fake. Strong DMARC + SPF means hard to impersonate.

    Use when: you have the sender's / company's domain.
    """
    result = await domain_auth_col.run(params.domain)
    return render(result, params.response_format)


@mcp.tool(name="check_typosquatting", annotations={"title": "Check Typosquatting", **_READONLY})
async def check_typosquatting(params: TyposquatInput) -> str:
    """Detect lookalike / typosquatting / homograph domains (offline, no key):
    brand embedded with extra words ('google-careers'), near-miss typos
    ('linkedln'), IDN/punycode confusables, and high-abuse TLDs ('.top').

    Use when: you have a domain and a real brand it might be impersonating.
    """
    result = await typosquat_col.run(params.domain, params.brand)
    return render(result, params.response_format)


# --------------------------------------------------------------------------- #
# Single unified entry point: the agent decides which of the tools to run.
# --------------------------------------------------------------------------- #
@mcp.prompt(name="analyze",
            description="One entry point: analyze anything scam-related — a pasted "
                        "recruiter message/offer, a company name, a person/handle, a "
                        "URL, or email headers. The agent auto-detects what it's given "
                        "and runs the right tools.")
def analyze(input: str) -> str:
    """Single, comprehensive workflow. The agent chooses tools autonomously."""
    return f"""You are a cyber-intelligence analyst. Assess whether the following is a \
job/recruiter scam. The INPUT may be a pasted recruiter message or job offer, OR just \
a company name, a person's name/handle, a URL/domain, or raw email headers — first \
work out what you were given, then investigate autonomously. Only run tools that fit \
the entities actually present; skip the rest.

INPUT:
---
{input}
---

1) UNDERSTAND & EXTRACT
   - If it's a message/offer: call `extract_entities` (emails, domains, URLs,
     LinkedIn URLs, phones, IPs, crypto addresses, off-platform mentions) and
     `check_scam_patterns` (advance fee, fake check, task scam, crypto, urgency…).
   - If raw email headers are present: `parse_email_headers` (SPF/DKIM/DMARC,
     From vs Reply-To mismatch, real originating IP).

2) CHECK EACH ENTITY (only those present)
   - email → check_email, check_email_footprint, check_domain_auth
   - domain / link → check_domain (age), check_certificate_transparency,
     check_typosquatting (brand=claimed company), check_url
   - real brand domain → find_lookalike_domains
   - phone → check_phone · crypto address → check_crypto_address
   - originating IP → check_ip · recruiter handle → check_username

3) VERIFY THE COMPANY (if a company is named)
   - verify_company (GLEIF + SEC). Find its REAL website via web search.
   - FIRST establish the company's country (GLEIF jurisdiction, stated HQ address,
     the website's ccTLD, or a web search) — do NOT assume a default region.
   - SMALL/local company (not in registries): search_company_news with that
     `country` (or pass `company_domain` so it infers the region from the ccTLD),
     verify_address (stated HQ), check_github_org (if they claim to build tech).
   - ORG CHART: web-search + fetch the company's Team/About page and confirm the
     recruiter is really listed in that role (no free structured org-chart source).

4) LINKEDIN / PERSON DEEP-DIVE (use YOUR OWN web search to discover; never fetch
   linkedin.com live — use fetch_archived_page for archived content)
   - Person named → web-search `site:linkedin.com/in "<name>" "<company>"`.
   - Company but no URL → web-search `site:linkedin.com/company "<company>"`.
   - For each LinkedIn URL: fetch_archived_page + check_wayback (age). Compare the
     archived headline/company to what's claimed — mismatch is a strong signal.
   - Pivot person↔company and cross-check consistency.

5) TEXTUAL RED FLAGS (your own judgment): urgency/pressure, up-front payment,
   asking to download/run code or apps for an interview, request for bank/ID/crypto,
   moving to WhatsApp/Telegram, too-good pay, no interview, mismatched names/domains.

6) VERDICT
   - Overall risk: HIGH / MEDIUM / LOW + confidence.
   - Bullet the concrete signals, citing each tool's finding.
   - Actionable advice (e.g. confirm via the company's verified site, never the
     offer's links).
   - Weight: a direct contradiction (lookalike domain, mismatched company, listed
     scam address) outweighs mere absence of evidence (no LEI, no archive). Treat
     all signals as probabilistic, not proof. LinkedIn hides account-creation dates,
     so use check_wayback as an age proxy."""


def main() -> None:
    """Entry point. Defaults to stdio (Claude Desktop / Claude Code).

    Use --http to serve over Streamable HTTP for remote clients such as
    Claude.ai web custom connectors (expose the port via a public HTTPS URL):

        jobverify-mcp --http --host 127.0.0.1 --port 8000
    """
    import argparse

    parser = argparse.ArgumentParser(prog="jobverify-mcp")
    parser.add_argument("--http", action="store_true",
                        help="Serve over Streamable HTTP instead of stdio.")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Host to bind for --http (default: 127.0.0.1).")
    parser.add_argument("--port", type=int, default=8000,
                        help="Port to bind for --http (default: 8000).")
    args = parser.parse_args()

    if args.http:
        mcp.settings.host = args.host
        mcp.settings.port = args.port
        mcp.run(transport="streamable-http")
    else:
        mcp.run()


if __name__ == "__main__":
    main()
