"""Tests for graph output (Mermaid and DOT)."""

from __future__ import annotations

from pathlib import Path

from attackchainbuilder.models import AttackChain, ChainStep, KillPhase
from attackchainbuilder.report.graph import write_dot, write_mermaid


def _sample_chains() -> list[AttackChain]:
    return [
        AttackChain(
            steps=[
                ChainStep(
                    cve_id="CVE-2021-44228", phase=KillPhase.INITIAL_ACCESS,
                    tactic_id="TA0001", tactic_name="Initial Access",
                    p_exploit=0.95, cvss=10.0, severity="CRITICAL",
                ),
                ChainStep(
                    cve_id="CVE-2023-22515", phase=KillPhase.IMPACT,
                    tactic_id="TA0040", tactic_name="Impact",
                    p_exploit=0.9, cvss=10.0, severity="CRITICAL",
                ),
            ],
            chain_score=95.0,
        ),
        AttackChain(
            steps=[
                ChainStep(
                    cve_id="CVE-2022-26134", phase=KillPhase.INITIAL_ACCESS,
                    tactic_id="TA0001", tactic_name="Initial Access",
                    p_exploit=0.9, cvss=9.8, severity="CRITICAL",
                ),
                ChainStep(
                    cve_id="CVE-2021-3156", phase=KillPhase.PRIVILEGE_ESCALATION,
                    tactic_id="TA0004", tactic_name="Privilege Escalation",
                    p_exploit=0.85, cvss=7.8, severity="HIGH",
                ),
            ],
            chain_score=85.0,
        ),
    ]


def test_write_mermaid_separate(tmp_path: Path):
    path = tmp_path / "chains.mmd"
    write_mermaid(_sample_chains(), path, merge=False)
    content = path.read_text(encoding="utf-8")
    assert "flowchart LR" in content
    assert "CVE-2021-44228" in content
    assert "CVE-2023-22515" in content
    assert "CVE-2022-26134" in content
    assert "-->" in content


def test_write_mermaid_merged(tmp_path: Path):
    path = tmp_path / "chains.mmd"
    write_mermaid(_sample_chains(), path, merge=True)
    content = path.read_text(encoding="utf-8")
    assert "subgraph chain_1" in content
    assert "subgraph chain_2" in content
    assert "end" in content


def test_write_dot_separate(tmp_path: Path):
    path = tmp_path / "chains.dot"
    write_dot(_sample_chains(), path, merge=False)
    content = path.read_text(encoding="utf-8")
    assert "digraph" in content
    assert "CVE-2021-44228" in content
    assert "->" in content
    assert "fillcolor" in content


def test_write_dot_merged(tmp_path: Path):
    path = tmp_path / "chains.dot"
    write_dot(_sample_chains(), path, merge=True)
    content = path.read_text(encoding="utf-8")
    assert "subgraph cluster_1" in content
    assert "subgraph cluster_2" in content


def test_write_mermaid_empty(tmp_path: Path):
    path = tmp_path / "empty.mmd"
    write_mermaid([], path, merge=False)
    assert path.exists()


def test_write_dot_empty(tmp_path: Path):
    path = tmp_path / "empty.dot"
    write_dot([], path, merge=False)
    assert path.exists()
