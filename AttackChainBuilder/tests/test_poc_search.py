"""Tests for GitHub PoC search module (all mocked)."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from attackchainbuilder.poc_search import PoCResult, search_pocs, search_pocs_batch


@patch("attackchainbuilder.poc_search.urllib.request.urlopen")
def test_search_pocs_success(mock_urlopen):
    response_data = {
        "items": [
            {
                "html_url": "https://github.com/test/log4j-poc",
                "full_name": "test/log4j-poc",
                "description": "PoC for Log4Shell",
                "stargazers_count": 150,
                "forks_count": 30,
                "language": "Python",
                "pushed_at": "2024-01-15T00:00:00Z",
            },
            {
                "html_url": "https://github.com/test2/small-poc",
                "full_name": "test2/small-poc",
                "description": "Small PoC",
                "stargazers_count": 2,
                "forks_count": 0,
                "language": "Bash",
                "pushed_at": "2023-06-01T00:00:00Z",
            },
        ]
    }
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(response_data).encode("utf-8")
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)
    mock_urlopen.return_value = mock_response

    results = search_pocs("CVE-2021-44228")
    assert len(results) == 2
    assert results[0].url == "https://github.com/test/log4j-poc"
    assert results[0].stars == 150
    assert results[0].verified is True
    assert results[1].stars == 2
    assert results[1].verified is False


@patch("attackchainbuilder.poc_search.urllib.request.urlopen")
def test_search_pocs_network_error(mock_urlopen):
    from urllib.error import URLError
    mock_urlopen.side_effect = URLError("connection refused")
    results = search_pocs("CVE-2026-9999")
    assert results == []


@patch("attackchainbuilder.poc_search.urllib.request.urlopen")
def test_search_pocs_empty_results(mock_urlopen):
    response_data = {"items": []}
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(response_data).encode("utf-8")
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)
    mock_urlopen.return_value = mock_response

    results = search_pocs("CVE-2026-0001")
    assert results == []


@patch("attackchainbuilder.poc_search.search_pocs")
def test_search_pocs_batch(mock_search):
    mock_search.side_effect = lambda cve_id, **kw: [
        PoCResult(url="https://github.com/test/poc", name="test/poc", description="", stars=10, forks=1, language="Python", pushed_at="2024-01-01", verified=True)
    ] if cve_id == "CVE-2021-44228" else []

    results = search_pocs_batch(["CVE-2021-44228", "CVE-2026-9999"])
    assert "CVE-2021-44228" in results
    assert "CVE-2026-9999" not in results
