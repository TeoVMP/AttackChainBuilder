"""Extract structured technical exploitation details from CVE data.

Parses CVSS vector metrics, CWE, description, and PoC data to produce
a human-readable ExploitDetails with attack prerequisites, method,
impact summary, and detection opportunities.
"""

from __future__ import annotations

import re

from attackchainbuilder.models import CveRecord, ExploitDetails

# CVSS metric value labels
_AV_LABELS = {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}
_AC_LABELS = {"L": "Low", "H": "High"}
_PR_LABELS = {"N": "None", "L": "Low", "H": "High"}
_UI_LABELS = {"N": "None", "R": "Required"}
_S_LABELS = {"U": "Unchanged", "C": "Changed"}
_CIA_LABELS = {"H": "High", "L": "Low", "N": "None"}

# CWE → exploitation method mapping
_CWE_METHODS: dict[str, str] = {
    "CWE-89": "SQL injection",
    "CWE-78": "OS command injection",
    "CWE-79": "Cross-site scripting (XSS)",
    "CWE-94": "Code injection",
    "CWE-502": "Unsafe deserialization",
    "CWE-22": "Path traversal",
    "CWE-269": "Improper privilege management",
    "CWE-287": "Authentication bypass",
    "CWE-787": "Out-of-bounds write (memory corruption)",
    "CWE-416": "Use-after-free (memory corruption)",
    "CWE-190": "Integer overflow",
    "CWE-120": "Buffer overflow",
    "CWE-121": "Stack-based buffer overflow",
    "CWE-122": "Heap-based buffer overflow",
    "CWE-125": "Out-of-bounds read",
    "CWE-200": "Information disclosure",
    "CWE-352": "Cross-site request forgery (CSRF)",
    "CWE-434": "Unrestricted file upload",
    "CWE-611": "XML external entity (XXE) injection",
    "CWE-918": "Server-side request forgery (SSRF)",
    "CWE-917": "Expression language injection (OGNL/SpEL)",
    "CWE-506": "Embedded malicious code",
    "CWE-912": "Hidden functionality / backdoor",
}

# Detection patterns by exploitation method
_DETECTION_MAP: dict[str, list[str]] = {
    "sql_injection": ["WAF: SQL syntax patterns in requests", "Database query logging", "IDS: UNION/SELECT payloads"],
    "command_injection": ["WAF: shell metacharacters (;|&`$)", "Process execution monitoring", "IDS: reverse shell patterns"],
    "deserialization": ["WAF: serialized object markers", "Java/PHP deserialization monitoring", "Network: outbound LDAP/RMI"],
    "rce_jndi": ["WAF: ${jndi:ldap:// patterns", "DNS: suspicious LDAP lookups", "Egress filtering on LDAP ports"],
    "buffer_overflow": ["IDS: NOP sled patterns", "Memory protection alerts (ASLR/DEP)", "Crash dump analysis"],
    "auth_bypass": ["Auth failure rate monitoring", "Session anomaly detection", "WAF: auth bypass patterns"],
    "path_traversal": ["WAF: ../ patterns", "File access monitoring", "IDS: directory traversal payloads"],
    "xss": ["WAF: script/event handler patterns", "CSP violation reports", "Input sanitization logs"],
    "ssrf": ["WAF: internal IP/range requests", "DNS rebinding detection", "Egress filtering"],
    "ransomware": ["File entropy monitoring", "Mass file rename detection", "Backup integrity checks"],
}


def _parse_cvss_vector(vector: str | None) -> dict[str, str]:
    if not vector:
        return {}
    text = vector.strip().upper()
    if not text.startswith("CVSS:3"):
        return {}
    metrics: dict[str, str] = {}
    for part in text.split("/")[1:]:
        if ":" in part:
            key, val = part.split(":", 1)
            metrics[key] = val
    return metrics


def _infer_method(cwe: list[str], description: str | None) -> str | None:
    """Infer exploitation method from CWE and description keywords."""
    # CWE-based
    for cwe_id in cwe:
        if cwe_id in _CWE_METHODS:
            return _CWE_METHODS[cwe_id]

    desc = (description or "").lower()

    # Keyword-based fallbacks
    if re.search(r"jndi|log4j|log4shell", desc):
        return "RCE via JNDI injection (Log4Shell-style)"
    if re.search(r"deserializ", desc):
        return "Unsafe deserialization"
    if re.search(r"command.?inject|os.?command", desc):
        return "OS command injection"
    if re.search(r"sql.?inject|sqli", desc):
        return "SQL injection"
    if re.search(r"buffer.?overflow|heap.?overflow|stack.?overflow", desc):
        return "Buffer overflow (memory corruption)"
    if re.search(r"use.?after.?free", desc):
        return "Use-after-free (memory corruption)"
    if re.search(r"privilege.?escalation|escalat", desc):
        return "Privilege escalation"
    if re.search(r"authentication.?bypass|auth.?bypass", desc):
        return "Authentication bypass"
    if re.search(r"remote.?code.?execution|\brce\b|code.?execution", desc):
        return "Remote code execution"
    if re.search(r"cross.?site.?script|\bxss\b", desc):
        return "Cross-site scripting (XSS)"
    if re.search(r"ssrf|server.?side.?request", desc):
        return "Server-side request forgery (SSRF)"
    if re.search(r"path.?traversal|directory.?traversal", desc):
        return "Path traversal"
    return None


def _build_prerequisites(metrics: dict[str, str]) -> list[str]:
    """Build human-readable prerequisites from CVSS metrics."""
    prereqs: list[str] = []

    av = metrics.get("AV", "")
    pr = metrics.get("PR", "")
    ui = metrics.get("UI", "")
    ac = metrics.get("AC", "")

    # Attack vector
    if av == "N":
        prereqs.append("Network access to vulnerable service")
    elif av == "A":
        prereqs.append("Adjacent network access")
    elif av == "L":
        prereqs.append("Local access to the system")

    # Privileges
    if pr == "N":
        prereqs.append("No authentication required")
    elif pr == "L":
        prereqs.append("Low-privilege user account required")
    elif pr == "H":
        prereqs.append("High-privilege / admin account required")

    # User interaction
    if ui == "R":
        prereqs.append("User interaction required (e.g. click link, open file)")

    # Complexity
    if ac == "H":
        prereqs.append("Specific system configuration required")

    return prereqs


def _build_impact_summary(metrics: dict[str, str], description: str | None) -> str:
    """Build a human-readable impact summary."""
    c = metrics.get("C", "N")
    i = metrics.get("I", "N")
    a = metrics.get("A", "N")
    scope = metrics.get("S", "U")

    impacts: list[str] = []
    if c == "H":
        impacts.append("full data exfiltration")
    elif c == "L":
        impacts.append("limited data disclosure")

    if i == "H":
        impacts.append("complete system compromise")
    elif i == "L":
        impacts.append("limited modification")

    if a == "H":
        impacts.append("total service disruption")
    elif a == "L":
        impacts.append("degraded availability")

    if scope == "C":
        impacts.append("cross-boundary impact (scope change)")

    desc = (description or "").lower()
    if re.search(r"ransomware|encrypt", desc):
        impacts.append("ransomware deployment")
    if re.search(r"lateral|pivot|spread|worm", desc):
        impacts.append("lateral movement capability")

    if not impacts:
        return "Impact depends on context"

    return ", ".join(impacts).capitalize()


def _detect_maturity(pocs: list[dict]) -> str:
    """Determine exploit maturity from PoC data."""
    kinds = {p.get("kind", "") for p in pocs}
    if kinds & {"metasploit", "exploit-db"}:
        return "weaponized"
    if kinds & {"github-poc", "nuclei-template", "packetstorm"}:
        return "poc"
    if pocs:
        return "poc"
    return "theoretical"


def _get_detection_opportunities(method: str | None, desc: str | None) -> list[str]:
    """Suggest detection opportunities based on exploitation method."""
    detections: list[str] = []
    desc_lower = (desc or "").lower()

    if method and "jndi" in method.lower() or "log4j" in desc_lower:
        detections.extend(_DETECTION_MAP.get("rce_jndi", []))
    elif method and "sql" in method.lower():
        detections.extend(_DETECTION_MAP.get("sql_injection", []))
    elif method and "command" in method.lower():
        detections.extend(_DETECTION_MAP.get("command_injection", []))
    elif method and "deserializ" in method.lower():
        detections.extend(_DETECTION_MAP.get("deserialization", []))
    elif method and "buffer" in method.lower() or method and "overflow" in method.lower():
        detections.extend(_DETECTION_MAP.get("buffer_overflow", []))
    elif method and "auth" in method.lower():
        detections.extend(_DETECTION_MAP.get("auth_bypass", []))
    elif method and "path" in method.lower() or method and "traversal" in method.lower():
        detections.extend(_DETECTION_MAP.get("path_traversal", []))
    elif method and "xss" in method.lower():
        detections.extend(_DETECTION_MAP.get("xss", []))
    elif method and "ssrf" in method.lower():
        detections.extend(_DETECTION_MAP.get("ssrf", []))

    if re.search(r"ransomware|encrypt", desc_lower):
        detections.extend(_DETECTION_MAP.get("ransomware", []))

    if not detections:
        detections.append("Standard endpoint detection and logging")

    return detections


def _build_source_info(cve: CveRecord) -> list[dict]:
    """Build structured source information."""
    sources: list[dict] = []
    for src in cve.sources:
        credibility = "HIGH" if "cisa-kev" in src else "MEDIUM"
        sources.append({"name": src, "credibility": credibility})
    return sources


def _build_poc_info(cve: CveRecord) -> list[dict]:
    """Build structured PoC information."""
    return [
        {
            "url": p.get("url", ""),
            "kind": p.get("kind", "unknown"),
            "origin": p.get("origin", ""),
        }
        for p in cve.pocs
    ]


def extract_details(cve: CveRecord) -> ExploitDetails:
    """Extract full technical exploitation details from a CVE record."""
    metrics = _parse_cvss_vector(cve.cvss_vector)
    method = _infer_method(cve.cwe, cve.description)
    prereqs = _build_prerequisites(metrics)
    impact = _build_impact_summary(metrics, cve.description)
    maturity = _detect_maturity(cve.pocs)
    detections = _get_detection_opportunities(method, cve.description)
    sources = _build_source_info(cve)
    pocs = _build_poc_info(cve)

    return ExploitDetails(
        attack_vector=_AV_LABELS.get(metrics.get("AV", "")),
        attack_complexity=_AC_LABELS.get(metrics.get("AC", "")),
        privileges_required=_PR_LABELS.get(metrics.get("PR", "")),
        user_interaction=_UI_LABELS.get(metrics.get("UI", "")),
        scope=_S_LABELS.get(metrics.get("S", "")),
        impact_confidentiality=_CIA_LABELS.get(metrics.get("C", "")),
        impact_integrity=_CIA_LABELS.get(metrics.get("I", "")),
        impact_availability=_CIA_LABELS.get(metrics.get("A", "")),
        exploitation_method=method,
        prerequisites=prereqs,
        impact_summary=impact,
        detection_opportunities=detections,
        sources=sources,
        pocs=pocs,
        exploit_maturity=maturity,
    )
