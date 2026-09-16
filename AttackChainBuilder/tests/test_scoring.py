"""Tests for scoring engine."""

from __future__ import annotations

from attackchainbuilder.classify import classify_all
from attackchainbuilder.loader import load
from attackchainbuilder.models import (
    AttackChain,
    ChainStep,
    CveRecord,
    KillPhase,
    TargetContext,
)
from attackchainbuilder.scoring import compute_chain_scores, p_exploit


def test_p_exploit_high_cvss_kev():
    cve = CveRecord(
        cve_id="CVE-2026-0001",
        cvss=10.0,
        confidence="HIGH",
        sources=["cisa-kev"],
        pocs=[{"url": "x", "kind": "exploit-db", "origin": "osv"}],
    )
    p = p_exploit(cve)
    assert p > 0.9
    assert p <= 0.98


def test_p_exploit_low_cvss():
    cve = CveRecord(cve_id="CVE-2026-0002", cvss=3.0, confidence="LOW")
    p = p_exploit(cve)
    assert p < 0.5
    assert p >= 0.05


def test_p_exploit_clamped():
    cve = CveRecord(cve_id="CVE-2026-0003", cvss=None, confidence="LOW")
    p = p_exploit(cve)
    assert p >= 0.05


def test_p_exploit_ransomware_bonus():
    cve_base = CveRecord(cve_id="CVE-2026-0004", cvss=8.0, confidence="HIGH")
    cve_ransom = CveRecord(
        cve_id="CVE-2026-0005", cvss=8.0, confidence="HIGH", ransomware_use="Known"
    )
    assert p_exploit(cve_ransom) > p_exploit(cve_base)


def test_compute_chain_scores(sample_json_path):
    cves = load(sample_json_path)
    classify_all(cves)
    # Build a simple chain from first available steps
    steps = []
    for cve in cves:
        if cve.phase is not None and cve.phase == KillPhase.INITIAL_ACCESS and not steps:
            steps.append(ChainStep(
                cve_id=cve.cve_id,
                phase=cve.phase,
                tactic_id="TA0001",
                tactic_name="Initial Access",
                techniques=cve.techniques[:],
                p_exploit=p_exploit(cve),
                cvss=cve.cvss,
                severity=cve.severity,
                software_tokens=cve.software_tokens,
            ))
        elif cve.phase is not None and cve.phase == KillPhase.IMPACT and len(steps) == 1:
            steps.append(ChainStep(
                cve_id=cve.cve_id,
                phase=cve.phase,
                tactic_id="TA0040",
                tactic_name="Impact",
                techniques=cve.techniques[:],
                p_exploit=p_exploit(cve),
                cvss=cve.cvss,
                severity=cve.severity,
                software_tokens=cve.software_tokens,
            ))
            break

    if len(steps) == 2:
        chain = AttackChain(steps=steps)
        context = TargetContext()
        compute_chain_scores(chain, context, set())
        assert chain.exploitability > 0
        assert chain.severity_mix > 0
        assert chain.chain_score > 0
        assert chain.coverage_ratio > 0


def test_chain_score_geometric_mean():
    """Chain score should be geometric mean of exploitability and severity_mix."""
    steps = [
        ChainStep(
            cve_id="CVE-2026-0001", phase=KillPhase.INITIAL_ACCESS,
            tactic_id="TA0001", tactic_name="Initial Access",
            p_exploit=0.9, cvss=9.8, severity="CRITICAL",
        ),
        ChainStep(
            cve_id="CVE-2026-0002", phase=KillPhase.IMPACT,
            tactic_id="TA0040", tactic_name="Impact",
            p_exploit=0.8, cvss=8.0, severity="HIGH",
        ),
    ]
    chain = AttackChain(steps=steps)
    compute_chain_scores(chain, TargetContext(), set())
    # Score = 100 * sqrt(exploitability * severity_mix)
    expected = round(100.0 * (chain.exploitability * chain.severity_mix) ** 0.5, 1)
    assert chain.chain_score == expected
