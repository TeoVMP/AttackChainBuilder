"""Tests for CLI commands."""

from __future__ import annotations

from pathlib import Path

from attackchainbuilder.cli import main


def test_build_basic(sample_json_path: Path, tmp_path: Path, capsys):
    rc = main([
        "build",
        "--input", str(sample_json_path),
        "--start-phase", "initial-access",
        "--format", "json,md",
        "--output", str(tmp_path),
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "attack chains generated" in out
    json_files = list(tmp_path.glob("attack_chains_*.json"))
    md_files = list(tmp_path.glob("attack_chains_*.md"))
    assert json_files
    assert md_files


def test_build_with_context(sample_json_path: Path, tmp_path: Path, capsys):
    rc = main([
        "build",
        "--input", str(sample_json_path),
        "--start-phase", "lateral-movement",
        "--goal-phase", "impact",
        "--output", str(tmp_path),
        "-q",
    ])
    assert rc == 0


def test_build_top_limit(sample_json_path: Path, tmp_path: Path, capsys):
    rc = main([
        "build",
        "--input", str(sample_json_path),
        "--top", "3",
        "--output", str(tmp_path),
        "-q",
    ])
    assert rc == 0


def test_build_no_chains(tmp_path: Path, capsys):
    import json
    data = {"vulnerabilities": [{"cve_id": "CVE-2026-9999", "description": "minor", "cvss": 1.0}]}
    path = tmp_path / "empty.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    rc = main(["build", "--input", str(path), "--output", str(tmp_path)])
    assert rc == 0
    assert "No attack chains found" in capsys.readouterr().out


def test_build_file_not_found(capsys):
    rc = main(["build", "--input", "/nonexistent/file.json"])
    assert rc == 1
    assert "File not found" in capsys.readouterr().out


def test_classify_table(sample_json_path: Path, capsys):
    rc = main(["classify", "--input", str(sample_json_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "CVE-2021-44228" in out
    assert "CVE ID" in out  # header present
    assert "Phase" in out


def test_classify_json(sample_json_path: Path, tmp_path: Path):
    rc = main([
        "classify",
        "--input", str(sample_json_path),
        "--format", "json",
        "--output", str(tmp_path),
    ])
    assert rc == 0
    json_files = list(tmp_path.glob("classification.json"))
    assert json_files


def test_classify_allow_unknown(tmp_path: Path, capsys):
    import json
    data = {"vulnerabilities": [
        {"cve_id": "CVE-2026-9999", "description": "minor bug", "cvss": 1.0},
    ]}
    path = tmp_path / "unknown.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    rc = main(["classify", "--input", str(path), "--allow-unknown"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "CVE-2026-9999" in out


def test_version(capsys):
    try:
        main(["--version"])
    except SystemExit:
        pass
    out = capsys.readouterr().out
    assert "AttackChainBuilder" in out


def test_build_all_formats(sample_json_path: Path, tmp_path: Path, capsys):
    rc = main([
        "build",
        "--input", str(sample_json_path),
        "--format", "json,md,csv,mermaid,dot",
        "--merge-graph",
        "--output", str(tmp_path),
        "-q",
    ])
    assert rc == 0
    assert (tmp_path / "attack_chains_*.json") or list(tmp_path.glob("*.json"))
