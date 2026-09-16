"""Tests for CVE classification (phase + technique inference)."""

from __future__ import annotations

from attackchainbuilder.classify import classify_all, classify_cve
from attackchainbuilder.loader import load
from attackchainbuilder.models import CveRecord, KillPhase


def test_classify_cve_remote_rce():
    cve = CveRecord(
        cve_id="CVE-2026-0001",
        description="Remote code execution in Apache web server via crafted HTTP request",
        cvss=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )
    classify_cve(cve)
    assert cve.phase == KillPhase.EXECUTION  # RCE keyword overrides vector INITIAL_ACCESS
    assert cve.phase_confidence == "HIGH"


def test_classify_cve_privilege_escalation():
    cve = CveRecord(
        cve_id="CVE-2026-0002",
        description="Local privilege escalation in Linux kernel via use-after-free",
        cvss=7.8,
        cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    )
    classify_cve(cve)
    assert cve.phase == KillPhase.PRIVILEGE_ESCALATION
    assert cve.phase_confidence == "HIGH"


def test_classify_cve_keyword_only():
    cve = CveRecord(
        cve_id="CVE-2026-0003",
        description="SQL injection in login form allows authentication bypass",
        cvss=8.5,
    )
    classify_cve(cve)
    assert cve.phase == KillPhase.INITIAL_ACCESS
    assert cve.phase_confidence == "MEDIUM"


def test_classify_cve_cwe_hint():
    cve = CveRecord(
        cve_id="CVE-2026-0004",
        description="Buffer overflow in network service",
        cvss=6.5,
        cwe=["CWE-120"],
    )
    classify_cve(cve)
    assert cve.phase == KillPhase.PRIVILEGE_ESCALATION


def test_classify_cve_unknown():
    cve = CveRecord(
        cve_id="CVE-2026-0005",
        description="Minor information disclosure",
        cvss=2.0,
    )
    classify_cve(cve)
    assert cve.phase is None
    assert cve.phase_confidence == "LOW"


def test_classify_cve_ransomware():
    cve = CveRecord(
        cve_id="CVE-2026-0006",
        description="Ransomware encryptor deployment via remote access",
        cvss=9.5,
        ransomware_use="Known",
    )
    classify_cve(cve)
    assert cve.phase == KillPhase.IMPACT


def test_classify_cve_lateral_movement():
    cve = CveRecord(
        cve_id="CVE-2026-0007",
        description="Network worm propagation via SMB vulnerability allows lateral movement across segments",
        cvss=9.0,
    )
    classify_cve(cve)
    assert cve.phase == KillPhase.LATERAL_MOVEMENT


def test_classify_cve_techniques_populated():
    cve = CveRecord(
        cve_id="CVE-2026-0008",
        description="Remote code execution via command injection in web application",
        cvss=9.8,
    )
    classify_cve(cve)
    assert len(cve.techniques) > 0
    assert any("T1059" in t for t in cve.techniques)  # Command injection


def test_classify_all(sample_json_path):
    cves = load(sample_json_path)
    classify_all(cves)
    classified = [c for c in cves if c.phase is not None]
    assert len(classified) >= 4  # most should classify


def test_classify_cve_persistence():
    cve = CveRecord(
        cve_id="CVE-2026-0009",
        description="Persistent backdoor installed via scheduled task cron job for maintaining access",
        cvss=8.0,
    )
    classify_cve(cve)
    assert cve.phase == KillPhase.PERSISTENCE
