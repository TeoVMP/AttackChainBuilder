"""Tests for technical exploitation details extraction."""

from __future__ import annotations

from attackchainbuilder.details import extract_details
from attackchainbuilder.models import CveRecord


def test_extract_details_full_vector():
    cve = CveRecord(
        cve_id="CVE-2026-0001",
        description="Remote code execution in Apache web server via JNDI injection",
        cvss=10.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        cwe=["CWE-502"],
        affected_software=["apache log4j"],
        sources=["cisa-kev"],
        confidence="HIGH",
        pocs=[{"url": "https://exploit-db.com/50592", "kind": "exploit-db", "origin": "osv"}],
        ransomware_use="Known",
    )
    details = extract_details(cve)

    assert details.attack_vector == "Network"
    assert details.attack_complexity == "Low"
    assert details.privileges_required == "None"
    assert details.user_interaction == "None"
    assert details.scope == "Changed"
    assert details.impact_confidentiality == "High"
    assert details.impact_integrity == "High"
    assert details.impact_availability == "High"
    assert details.exploitation_method == "Unsafe deserialization"
    assert details.exploit_maturity == "weaponized"
    assert len(details.prerequisites) > 0
    assert details.impact_summary is not None
    assert len(details.detection_opportunities) > 0
    assert len(details.sources) == 1
    assert details.sources[0]["credibility"] == "HIGH"
    assert len(details.pocs) == 1


def test_extract_details_no_vector():
    cve = CveRecord(
        cve_id="CVE-2026-0002",
        description="SQL injection in login form",
        cvss=8.5,
    )
    details = extract_details(cve)
    assert details.exploitation_method == "SQL injection"
    assert details.attack_vector is None
    assert details.exploit_maturity == "theoretical"


def test_extract_details_local_lpe():
    cve = CveRecord(
        cve_id="CVE-2026-0003",
        description="Local privilege escalation via buffer overflow in sudo",
        cvss=7.8,
        cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        cwe=["CWE-122"],
    )
    details = extract_details(cve)
    assert details.attack_vector == "Local"
    assert details.privileges_required == "Low"
    assert "Local access" in details.prerequisites[0]


def test_extract_details_ransomware():
    cve = CveRecord(
        cve_id="CVE-2026-0004",
        description="Ransomware deployment via remote access vulnerability, encrypts all files",
        cvss=9.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )
    details = extract_details(cve)
    assert "ransomware" in details.impact_summary.lower()


def test_extract_details_auth_required():
    cve = CveRecord(
        cve_id="CVE-2026-0005",
        description="Command injection in admin panel",
        cvss=8.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
    )
    details = extract_details(cve)
    assert details.privileges_required == "High"
    assert any("admin" in p.lower() or "high" in p.lower() for p in details.prerequisites)


def test_extract_details_user_interaction():
    cve = CveRecord(
        cve_id="CVE-2026-0006",
        description="XSS in web application requires user to click malicious link",
        cvss=6.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
    )
    details = extract_details(cve)
    assert details.user_interaction == "Required"
    assert any("user interaction" in p.lower() for p in details.prerequisites)
