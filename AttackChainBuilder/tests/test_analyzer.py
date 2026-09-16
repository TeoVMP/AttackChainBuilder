"""Tests for viability analysis and false positive detection."""

from __future__ import annotations

from attackchainbuilder.analyzer import (
    analyze_chain,
    assess_viability,
    detect_false_positives,
    get_cve_fp_summary,
)
from attackchainbuilder.classify import classify_all
from attackchainbuilder.details import extract_details
from attackchainbuilder.loader import load
from attackchainbuilder.models import (
    AttackChain,
    ChainStep,
    CveRecord,
    KillPhase,
)


def test_detect_fp_theoretical_risk():
    cve = CveRecord(
        cve_id="CVE-2026-0001",
        description="Critical RCE vulnerability",
        cvss=9.8,
        sources=["github-advisories"],
    )
    fps = detect_false_positives(cve)
    flags = [f.flag for f in fps]
    assert "theoretical_risk" in flags


def test_detect_fp_low_confidence():
    cve = CveRecord(
        cve_id="CVE-2026-0002",
        description="Some bug",
        cvss=5.0,
        phase=None,
        phase_confidence="LOW",
    )
    fps = detect_false_positives(cve)
    flags = [f.flag for f in fps]
    assert "uncertain_classification" in flags


def test_detect_fp_old_no_kev():
    cve = CveRecord(
        cve_id="CVE-2015-0001",
        description="Old vulnerability in software",
        cvss=7.0,
        published="2015-03-15",
        sources=["github-advisories"],
    )
    fps = detect_false_positives(cve)
    flags = [f.flag for f in fps]
    assert "likely_patched" in flags


def test_detect_fp_vague_description():
    cve = CveRecord(
        cve_id="CVE-2026-0003",
        description="Bug",
        cvss=5.0,
    )
    fps = detect_false_positives(cve)
    flags = [f.flag for f in fps]
    assert "vague_description" in flags


def test_detect_fp_no_software():
    cve = CveRecord(
        cve_id="CVE-2026-0004",
        description="Some vulnerability with enough description length to pass",
        cvss=5.0,
        affected_software=[],
    )
    fps = detect_false_positives(cve)
    flags = [f.flag for f in fps]
    assert "no_software_info" in flags


def test_detect_fp_clean_cve():
    cve = CveRecord(
        cve_id="CVE-2026-0005",
        description="Well-documented RCE in Apache with known exploit and KEV entry",
        cvss=9.8,
        sources=["cisa-kev"],
        confidence="HIGH",
        pocs=[{"url": "https://exploit-db.com/12345", "kind": "exploit-db", "origin": "osv"}],
        affected_software=["apache httpd"],
        published="2026-01-15",
        phase=KillPhase.EXECUTION,
        phase_confidence="HIGH",
    )
    fps = detect_false_positives(cve)
    # Should have no significant flags
    high_fps = [f for f in fps if f.severity == "HIGH"]
    assert len(high_fps) == 0


def test_assess_viability_high():
    cve = CveRecord(
        cve_id="CVE-2026-0006",
        cvss=9.8,
        confidence="HIGH",
        sources=["cisa-kev"],
        pocs=[{"url": "x", "kind": "metasploit", "origin": "osv"}],
        ransomware_use="Known",
    )
    details = extract_details(cve)
    assert assess_viability(cve, details) == "HIGH"


def test_assess_viability_low():
    cve = CveRecord(
        cve_id="CVE-2026-0007",
        cvss=5.0,
        confidence="LOW",
        sources=[],
        pocs=[],
    )
    details = extract_details(cve)
    details.fp_flags = detect_false_positives(cve)
    assert assess_viability(cve, details) == "LOW"


def test_analyze_chain(sample_json_path):
    cves = load(sample_json_path)
    classify_all(cves)
    chain = AttackChain(
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
        ]
    )
    analyze_chain(chain, cves)
    assert chain.viability in ("HIGH", "MEDIUM", "LOW")
    assert len(chain.details) == 2
    assert chain.details[0].exploitation_method is not None


def test_get_cve_fp_summary(sample_json_path):
    cves = load(sample_json_path)
    classify_all(cves)
    summary = get_cve_fp_summary(cves)
    assert isinstance(summary, dict)
