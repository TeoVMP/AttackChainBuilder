"""Tests for report writers (JSON, Markdown, CSV)."""

from __future__ import annotations

import csv
import json

from attackchainbuilder.chain import build_chains
from attackchainbuilder.classify import classify_all
from attackchainbuilder.loader import load
from attackchainbuilder.models import AttackChain, ChainStep, KillPhase, TargetContext
from attackchainbuilder.report import write_reports
from attackchainbuilder.report.csv_out import safe_cell


def _sample_chain() -> AttackChain:
    return AttackChain(
        steps=[
            ChainStep(
                cve_id="CVE-2021-44228", phase=KillPhase.INITIAL_ACCESS,
                tactic_id="TA0001", tactic_name="Initial Access",
                techniques=["T1190", "T1059"], p_exploit=0.95, cvss=10.0,
                severity="CRITICAL", software_tokens=["apache", "log4j"],
            ),
            ChainStep(
                cve_id="CVE-2021-3156", phase=KillPhase.PRIVILEGE_ESCALATION,
                tactic_id="TA0004", tactic_name="Privilege Escalation",
                techniques=["T1068"], p_exploit=0.85, cvss=7.8,
                severity="HIGH", software_tokens=["sudo"],
            ),
            ChainStep(
                cve_id="CVE-2023-22515", phase=KillPhase.IMPACT,
                tactic_id="TA0040", tactic_name="Impact",
                techniques=["T1486"], p_exploit=0.9, cvss=10.0,
                severity="CRITICAL", software_tokens=["atlassian", "confluence"],
            ),
        ],
        exploitability=0.728,
        severity_mix=0.85,
        chain_score=78.9,
        coverage_ratio=0.43,
        software_link_strength=0.67,
    )


def _sample_meta() -> dict:
    return {
        "generated_at": "2026-09-15T12:00:00+00:00",
        "total_cves": 12,
        "chains_found": 1,
        "context": {
            "start_phase": "INITIAL_ACCESS",
            "goal_phase": "IMPACT",
            "software": ["apache"],
            "version": None,
            "max_steps": 5,
            "min_steps": 2,
        },
    }


def test_safe_cell_formula_injection():
    assert safe_cell("=1+1") == "'=1+1"
    assert safe_cell("+SUM(A1)") == "'+SUM(A1)"
    assert safe_cell("normal") == "normal"
    assert safe_cell(None) == ""


def test_write_json(tmp_path):
    chain = _sample_chain()
    path = tmp_path / "chains.json"
    from attackchainbuilder.report import json_out
    json_out.write([chain], path, _sample_meta())
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["chains_found"] == 1
    assert data["chains"][0]["rank"] == 1
    assert data["chains"][0]["chain_score"] == 78.9
    assert data["chains"][0]["steps"][0]["cve_id"] == "CVE-2021-44228"


def test_write_markdown(tmp_path):
    chain = _sample_chain()
    path = tmp_path / "chains.md"
    from attackchainbuilder.report import markdown
    markdown.write([chain], path, _sample_meta())
    text = path.read_text(encoding="utf-8")
    assert "AttackChainBuilder" in text
    assert "CVE-2021-44228" in text
    assert "INIT-ACCESS" in text
    assert "78.9" in text


def test_write_csv(tmp_path):
    chain = _sample_chain()
    path = tmp_path / "chains.csv"
    from attackchainbuilder.report import csv_out
    csv_out.write([chain], path, _sample_meta())
    with path.open(newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    assert rows[0][0] == "Rank"
    assert rows[1][0] == "1"
    # CVE IDs are in column 8
    cve_col = rows[0].index("CVE IDs")
    assert "CVE-2021-44228" in rows[1][cve_col]


def test_write_csv_sanitized(tmp_path):
    chain = _sample_chain()
    path = tmp_path / "chains.csv"
    from attackchainbuilder.report import csv_out
    csv_out.write([chain], path, _sample_meta())
    with path.open(newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    # Check no formula injection
    for row in rows:
        for cell in row:
            if cell:
                assert not cell.startswith("=")
                assert not cell.startswith("+")


def test_write_reports_full(sample_json_path, tmp_path):
    cves = load(sample_json_path)
    classify_all(cves)
    context = TargetContext(start_phase=KillPhase.INITIAL_ACCESS, goal_phase=KillPhase.IMPACT)
    chains = build_chains(cves, context)
    written = write_reports(
        chains, cves, context,
        ["json", "md", "csv", "mermaid", "dot"],
        tmp_path, merge_graph=False,
    )
    assert "json" in written
    assert "md" in written
    assert "csv" in written
    assert "mermaid" in written
    assert "dot" in written
    for path in written.values():
        assert path.exists()
        assert path.stat().st_size > 0


def test_write_reports_merge_graph(sample_json_path, tmp_path):
    cves = load(sample_json_path)
    classify_all(cves)
    context = TargetContext()
    chains = build_chains(cves, context)
    written = write_reports(
        chains, cves, context,
        ["mermaid", "dot"],
        tmp_path, merge_graph=True,
    )
    assert "mermaid" in written
    assert "dot" in written
    mmd = written["mermaid"].read_text(encoding="utf-8")
    assert "subgraph" in mmd
