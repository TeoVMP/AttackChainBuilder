"""Shared fixtures for AttackChainBuilder tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

SAMPLE_EH_JSON = {
    "tool": "ExploitHunter 2.0.0",
    "generated_at": "2026-09-15T12:00:00+00:00",
    "year": "2026",
    "sources": ["CISA KEV catalog"],
    "count": 5,
    "vulnerabilities": [
        {
            "cve_id": "CVE-2021-44228",
            "description": "Apache Log4j2 remote code execution via JNDI lookup. Allows unauthenticated attacker to execute arbitrary code.",
            "cvss": 10.0,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "cwe": ["CWE-502"],
            "affected_software": ["apache log4j"],
            "pocs": [
                {"url": "https://www.exploit-db.com/exploits/50592", "kind": "exploit-db", "origin": "osv"}
            ],
            "sources": ["cisa-kev"],
            "confidence": "HIGH",
            "published": "2021-12-10",
            "kev_due_date": "2021-12-24",
            "ransomware_use": "Known",
        },
        {
            "cve_id": "CVE-2021-3156",
            "description": "Sudo privilege escalation via heap-based buffer overflow in sudoedit. Local user can gain root privileges.",
            "cvss": 7.8,
            "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "cwe": ["CWE-122"],
            "affected_software": ["sudo project sudo"],
            "pocs": [],
            "sources": ["cisa-kev"],
            "confidence": "HIGH",
            "published": "2021-01-26",
        },
        {
            "cve_id": "CVE-2017-0144",
            "description": "Windows SMB remote code execution vulnerability exploited by EternalBlue. Allows remote attackers to execute arbitrary code via crafted SMB packets.",
            "cvss": 9.8,
            "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cwe": ["CWE-119"],
            "affected_software": ["microsoft windows"],
            "pocs": [
                {"url": "https://github.com/rapid7/metasploit-framework/ms17_010_eternalblue.rb", "kind": "metasploit", "origin": "osv"}
            ],
            "sources": ["cisa-kev"],
            "confidence": "HIGH",
            "published": "2017-03-16",
            "ransomware_use": "Known",
        },
        {
            "cve_id": "CVE-2022-26134",
            "description": "Atlassian Confluence OGNL injection allows unauthenticated remote code execution.",
            "cvss": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cwe": ["CWE-917"],
            "affected_software": ["atlassian confluence server"],
            "pocs": [],
            "sources": ["cisa-kev"],
            "confidence": "HIGH",
            "published": "2022-06-02",
        },
        {
            "cve_id": "CVE-2023-22515",
            "description": "Atlassian Confluence privilege escalation vulnerability. Ransomware campaigns deploy destructive payloads after exploitation.",
            "cvss": 10.0,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "cwe": ["CWE-269"],
            "affected_software": ["atlassian confluence server"],
            "pocs": [],
            "sources": ["cisa-kev"],
            "confidence": "HIGH",
            "published": "2023-10-04",
            "ransomware_use": "Known",
        },
    ],
}


@pytest.fixture
def sample_json_path(tmp_path: Path) -> Path:
    path = tmp_path / "exploited_cves.json"
    path.write_text(json.dumps(SAMPLE_EH_JSON), encoding="utf-8")
    return path


@pytest.fixture
def sample_json_str() -> str:
    return json.dumps(SAMPLE_EH_JSON)
