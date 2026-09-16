"""Tests for debug mode output."""

from __future__ import annotations

from attackchainbuilder.classify import classify_all
from attackchainbuilder.debug import (
    debug_chain,
    debug_classify,
    debug_classify_all,
    debug_context,
)
from attackchainbuilder.loader import load
from attackchainbuilder.models import (
    AttackChain,
    ChainStep,
    CveRecord,
    KillPhase,
    TargetContext,
)


def test_debug_classify_basic():
    cve = CveRecord(
        cve_id="CVE-2026-0001",
        description="RCE in Apache",
        cvss=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        confidence="HIGH",
        sources=["cisa-kev"],
        phase=KillPhase.EXECUTION,
        phase_confidence="HIGH",
        techniques=["T1059"],
    )
    output = debug_classify(cve)
    assert "CVE-2026-0001" in output
    assert "EXECUTION" in output
    assert "CVSS" in output
    assert "p_exploit" in output


def test_debug_classify_all(sample_json_path):
    cves = load(sample_json_path)
    classify_all(cves)
    output = debug_classify_all(cves)
    assert "CLASSIFICATION DEBUG" in output
    for cve in cves:
        assert cve.cve_id in output


def test_debug_chain():
    chain = AttackChain(
        steps=[
            ChainStep(
                cve_id="CVE-2021-44228", phase=KillPhase.INITIAL_ACCESS,
                tactic_id="TA0001", tactic_name="Initial Access",
                techniques=["T1190"], p_exploit=0.95, cvss=10.0,
            ),
        ],
        chain_score=85.0,
        exploitability=0.95,
        viability="HIGH",
    )
    output = debug_chain(chain, 1)
    assert "Chain #1" in output
    assert "CVE-2021-44228" in output
    assert "p_exploit" in output


def test_debug_context():
    context = TargetContext(
        start_phase=KillPhase.LATERAL_MOVEMENT,
        goal_phase=KillPhase.IMPACT,
        software_tokens=["apache"],
    )
    output = debug_context(context)
    assert "LATERAL_MOVEMENT" in output
    assert "IMPACT" in output
    assert "apache" in output
