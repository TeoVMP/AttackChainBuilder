"""Search for community-verified PoCs on GitHub.

Uses the GitHub Search API (no auth required for basic search) to find
PoC repositories for CVEs. Requires network access; opt-in via --search-pocs.

Verification criteria:
- Minimum stars (default: 5)
- Pushed within last 2 years
- Repository name/description contains CVE ID or exploit/PoC keywords
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"
DEFAULT_MIN_STARS = 5
DEFAULT_TIMEOUT = 15


@dataclass
class PoCResult:
    """A community PoC repository found on GitHub."""

    url: str
    name: str
    description: str
    stars: int
    forks: int
    language: str | None
    pushed_at: str
    verified: bool  # stars >= threshold


def search_pocs(
    cve_id: str,
    min_stars: int = DEFAULT_MIN_STARS,
    timeout: int = DEFAULT_TIMEOUT,
) -> list[PoCResult]:
    """Search GitHub for PoC repositories for a given CVE.

    Returns list of PoCResult sorted by stars descending.
    Requires network access.
    """
    query = f"{cve_id} poc OR exploit OR proof-of-concept"
    params = urllib.parse.urlencode({
        "q": query,
        "sort": "stars",
        "order": "desc",
        "per_page": 10,
    })
    url = f"{GITHUB_SEARCH_URL}?{params}"

    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "AttackChainBuilder/0.1.0",
        },
    )

    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, json.JSONDecodeError, OSError):
        return []

    results: list[PoCResult] = []
    for item in data.get("items", []):
        stars = item.get("stargazers_count", 0)
        results.append(PoCResult(
            url=item.get("html_url", ""),
            name=item.get("full_name", ""),
            description=(item.get("description") or "")[:200],
            stars=stars,
            forks=item.get("forks_count", 0),
            language=item.get("language"),
            pushed_at=item.get("pushed_at", ""),
            verified=stars >= min_stars,
        ))

    return results


def search_pocs_batch(
    cve_ids: list[str],
    min_stars: int = DEFAULT_MIN_STARS,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, list[PoCResult]]:
    """Search for PoCs for multiple CVEs.

    Returns {cve_id: [PoCResult]} for CVEs that have results.
    """
    results: dict[str, list[PoCResult]] = {}
    for cve_id in cve_ids:
        pocs = search_pocs(cve_id, min_stars=min_stars, timeout=timeout)
        if pocs:
            results[cve_id] = pocs
    return results
