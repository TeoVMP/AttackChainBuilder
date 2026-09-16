"""Tests for the JSON loader."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from attackchainbuilder.loader import load


def test_load_returns_cve_records(sample_json_path: Path):
    records = load(sample_json_path)
    assert len(records) == 5
    assert records[0].cve_id == "CVE-2021-44228"
    assert records[0].cvss == 10.0
    assert records[0].cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert "CWE-502" in records[0].cwe
    assert "apache log4j" in records[0].affected_software


def test_load_tolerates_missing_fields(tmp_path: Path):
    data = {
        "vulnerabilities": [
            {"cve_id": "CVE-2026-0001"},
            {"cve_id": "CVE-2026-0002", "cvss": "not-a-number", "cwe": None},
        ]
    }
    path = tmp_path / "minimal.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    records = load(path)
    assert len(records) == 2
    assert records[0].cvss is None
    assert records[0].cwe == []
    assert records[1].cvss is None


def test_load_skips_entries_without_cve_id(tmp_path: Path):
    data = {"vulnerabilities": [{"description": "no cve"}, {"cve_id": ""}]}
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    records = load(path)
    assert len(records) == 0


def test_load_raises_on_invalid_json(tmp_path: Path):
    path = tmp_path / "bad.json"
    path.write_text("not json", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        load(path)


def test_load_raises_on_non_dict(tmp_path: Path):
    path = tmp_path / "list.json"
    path.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
    with pytest.raises(TypeError):
        load(path)


def test_load_raises_on_missing_vulnerabilities(tmp_path: Path):
    path = tmp_path / "novulns.json"
    path.write_text(json.dumps({"tool": "test"}), encoding="utf-8")
    with pytest.raises(TypeError):
        load(path)


def test_load_parses_pocs(sample_json_path: Path):
    records = load(sample_json_path)
    pocs = records[0].pocs
    assert len(pocs) == 1
    assert pocs[0]["url"] == "https://www.exploit-db.com/exploits/50592"
    assert pocs[0]["kind"] == "exploit-db"
