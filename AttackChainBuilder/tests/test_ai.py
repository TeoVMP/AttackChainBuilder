"""Tests for AI advisor module (all mocked, no network)."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from attackchainbuilder.ai import (
    _get_config,
    classify_with_ai,
    explain_chain,
)


def test_get_config_no_key(monkeypatch):
    monkeypatch.delenv("ACB_AI_API_KEY", raising=False)
    assert _get_config() is None


def test_get_config_with_key(monkeypatch):
    monkeypatch.setenv("ACB_AI_API_KEY", "test-key")
    monkeypatch.setenv("ACB_AI_BASE_URL", "https://test.api.com/v1")
    monkeypatch.setenv("ACB_AI_MODEL", "gpt-4o-mini")
    config = _get_config()
    assert config is not None
    assert config[0] == "https://test.api.com/v1"
    assert config[1] == "test-key"
    assert config[2] == "gpt-4o-mini"


def test_classify_with_ai_no_config(monkeypatch):
    monkeypatch.delenv("ACB_AI_API_KEY", raising=False)
    phase, rationale = classify_with_ai("RCE in web server", 9.8, ["apache"])
    assert phase is None
    assert rationale == ""


@patch("attackchainbuilder.ai.urllib.request.urlopen")
def test_classify_with_ai_success(mock_urlopen, monkeypatch):
    monkeypatch.setenv("ACB_AI_API_KEY", "test-key")

    response_data = {
        "choices": [{"message": {"content": '{"phase": "INITIAL_ACCESS", "rationale": "Remote unauthenticated RCE"}'}}]
    }
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(response_data).encode("utf-8")
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)
    mock_urlopen.return_value = mock_response

    phase, rationale = classify_with_ai("Remote code execution in Apache", 9.8, ["apache"])
    assert phase == "INITIAL_ACCESS"
    assert "Remote" in rationale


@patch("attackchainbuilder.ai.urllib.request.urlopen")
def test_classify_with_ai_invalid_json(mock_urlopen, monkeypatch):
    monkeypatch.setenv("ACB_AI_API_KEY", "test-key")

    mock_response = MagicMock()
    mock_response.read.return_value = b"not json at all"
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)
    mock_urlopen.return_value = mock_response

    phase, _rationale = classify_with_ai("test", 5.0, [])
    assert phase is None


@patch("attackchainbuilder.ai.urllib.request.urlopen")
def test_explain_chain_success(mock_urlopen, monkeypatch):
    monkeypatch.setenv("ACB_AI_API_KEY", "test-key")

    response_data = {
        "choices": [{"message": {"content": "This chain exploits Log4Shell for initial access, then escalates via sudo."}}]
    }
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(response_data).encode("utf-8")
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)
    mock_urlopen.return_value = mock_response

    steps = [
        {"cve_id": "CVE-2021-44228", "phase": "INITIAL_ACCESS", "cvss": 10.0, "description": "Log4Shell RCE"},
        {"cve_id": "CVE-2021-3156", "phase": "PRIVILEGE_ESCALATION", "cvss": 7.8, "description": "Sudo LPE"},
    ]
    result = explain_chain(steps, "testing context")
    assert result is not None
    assert "Log4Shell" in result


def test_explain_chain_no_config(monkeypatch):
    monkeypatch.delenv("ACB_AI_API_KEY", raising=False)
    result = explain_chain([{"cve_id": "CVE-2026-0001"}], "test")
    assert result is None
