"""Central configuration.

This server needs **no API keys**. Every data source is free and open:
local blocklists (FireHOL, Tor, Phishing.Database, URLhaus feed), the iptoasn
public-domain dataset, RDAP, DNS, Google's libphonenumber, the Internet Archive,
and the GLEIF LEI API. The only optional environment variable is a cache path.
"""

from __future__ import annotations

import os

# HTTP defaults
HTTP_TIMEOUT = 20.0
USER_AGENT = ("jobverify-mcp/0.1 (OSINT job-scam detection; "
              "+https://github.com/yessGlory17/job-verify)")


def cache_dir_override() -> str | None:
    """Optional override for where downloaded datasets are cached."""
    return os.environ.get("JOBVERIFY_CACHE") or None
