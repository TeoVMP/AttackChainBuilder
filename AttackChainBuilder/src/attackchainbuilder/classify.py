"""CVE → kill-chain phase + ATT&CK technique classification.

Classification priority (highest → lowest):
1. CVSS vector metrics (PR, AV, S, C/I/A) — most reliable
2. Description keywords — curated regex table
3. CWE hints — mapped to likely phases
4. Fallback: None (unknown) — excluded unless --allow-unknown
"""

from __future__ import annotations

import re

from attackchainbuilder.attack import match_techniques
from attackchainbuilder.models import CveRecord, KillPhase

# ---------------------------------------------------------------------------
# CVSS vector-based phase inference
# ---------------------------------------------------------------------------

def _parse_cvss_vector(vector: str | None) -> dict[str, str]:
    """Extract metric values from a CVSS:3.x vector string."""
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


def _infer_from_vector(vector: str | None, description: str | None) -> KillPhase | None:
    """Infer phase from CVSS vector metrics."""
    m = _parse_cvss_vector(vector)
    if not m:
        return None

    av = m.get("AV", "")
    pr = m.get("PR", "")
    ui = m.get("UI", "")
    scope = m.get("S", "")
    c = m.get("C", "")
    i = m.get("I", "")
    a = m.get("A", "")

    desc_lower = (description or "").lower()

    # Impact indicators → IMPACT
    if a == "H" and (ransomware_hint(desc_lower) or "destruction" in desc_lower):
        return KillPhase.IMPACT

    # Remote unauthenticated → likely INITIAL_ACCESS or EXECUTION
    if av == "N" and pr == "N" and ui == "N":
        if any(kw in desc_lower for kw in ("rce", "code execution", "command injection")):
            return KillPhase.EXECUTION
        return KillPhase.INITIAL_ACCESS

    # Scope change → often lateral movement
    if scope == "C" and av in ("N", "A"):
        return KillPhase.LATERAL_MOVEMENT

    # Local + low privileges → privilege escalation
    if av == "L" and pr in ("L", "H"):
        return KillPhase.PRIVILEGE_ESCALATION

    # Network + requires some privileges → could be lateral or priv-esc
    if av == "N" and pr == "L":
        if "lateral" in desc_lower or "pivot" in desc_lower:
            return KillPhase.LATERAL_MOVEMENT
        return KillPhase.PRIVILEGE_ESCALATION

    # High confidentiality + high integrity impact with network access
    if av == "N" and c == "H" and i == "H":
        return KillPhase.EXECUTION

    return None


# ---------------------------------------------------------------------------
# Keyword-based phase inference
# ---------------------------------------------------------------------------

_PHASE_KEYWORDS: list[tuple[KillPhase, re.Pattern[str]]] = [
    # Initial Access
    (KillPhase.INITIAL_ACCESS, re.compile(
        r"sql.?inject|sqli|authentication.?bypass|auth.?bypass|"
        r"public.?facing|web.?server|webshell|web.?shell|"
        r"default.?credential|default.?password|hardcoded|"
        r"unauthenticated|without.?auth|no.?auth",
        re.IGNORECASE,
    )),
    # Execution
    (KillPhase.EXECUTION, re.compile(
        r"remote.?code.?execution|\brce\b|command.?injection|"
        r"code.?execution|arbitrary.?code|arbitrary.?command|"
        r"deserialization|unsafe.?deserializ|eval.?injection|"
        r"template.?injection|expression.?language|"
        r"\bjndi\b|log4j|log4shell|os.?command|shell.?injection",
        re.IGNORECASE,
    )),
    # Persistence
    (KillPhase.PERSISTENCE, re.compile(
        r"persistence|backdoor|webshell|web.?shell|"
        r"scheduled.?task|cron|startup|autostart|"
        r"systemd.?service|dll.?injection|dll.?side.?load|"
        r"process.?injection|hijack",
        re.IGNORECASE,
    )),
    # Privilege Escalation
    (KillPhase.PRIVILEGE_ESCALATION, re.compile(
        r"privilege.?escalation|local.?privilege|\blpe\b|escalat|"
        r"\broot\b|kernel|sudo|pkexec|polkit|setuid|setgid|"
        r"buffer.?overflow|heap.?overflow|stack.?overflow|"
        r"use.?after.?free|race.?condition|type.?confusion|"
        r"integer.?overflow|memory.?corruption|baron.?samedit",
        re.IGNORECASE,
    )),
    # Credential Access
    (KillPhase.CREDENTIAL_ACCESS, re.compile(
        r"credential|password|hash.?dump|lsass|mimikatz|"
        r"token.?theft|kerberos|ntlm|sam.?database|"
        r"credential.?dump|password.?steal|session.?hijack|"
        r"kerberoast|asreproast|dcsync|dpapi|"
        r"man.?in.?the.?middle|mitm|arp.?spoof|dns.?poison",
        re.IGNORECASE,
    )),
    # Lateral Movement
    (KillPhase.LATERAL_MOVEMENT, re.compile(
        r"lateral|pivot|remote.?service|spread|worm|self.?propagat|"
        r"network.?propagation|eternal.?blue|bluekeep|"
        r"\bsmb\b|\brdp\b|\bssh\b|\bwinrm\b|\bwmi\b|\bdcom\b",
        re.IGNORECASE,
    )),
    # Impact
    (KillPhase.IMPACT, re.compile(
        r"ransomware|encrypt|data.?encrypted|crypto.?locker|"
        r"data.?destruct|wipe|destructive|shredder|"
        r"denial.?of.?service|\bdos\b|\bddos\b|"
        r"availability|resource.?exhaustion|"
        r"shadow.?copy|backup.?delet|inhibit.?recovery",
        re.IGNORECASE,
    )),
]


def _infer_from_keywords(description: str | None) -> KillPhase | None:
    if not description:
        return None
    for phase, pattern in _PHASE_KEYWORDS:
        if pattern.search(description):
            return phase
    return None


# ---------------------------------------------------------------------------
# CWE-based phase inference
# ---------------------------------------------------------------------------

_CWE_TO_PHASE: dict[str, KillPhase] = {
    "CWE-89": KillPhase.INITIAL_ACCESS,     # SQL Injection
    "CWE-78": KillPhase.EXECUTION,          # OS Command Injection
    "CWE-79": KillPhase.EXECUTION,          # XSS (client execution)
    "CWE-94": KillPhase.EXECUTION,          # Code Injection
    "CWE-502": KillPhase.EXECUTION,         # Deserialization
    "CWE-22": KillPhase.INITIAL_ACCESS,     # Path Traversal
    "CWE-269": KillPhase.PRIVILEGE_ESCALATION,  # Improper Privilege Management
    "CWE-287": KillPhase.INITIAL_ACCESS,    # Improper Authentication
    "CWE-787": KillPhase.PRIVILEGE_ESCALATION,  # Out-of-bounds Write
    "CWE-416": KillPhase.PRIVILEGE_ESCALATION,  # Use After Free
    "CWE-190": KillPhase.PRIVILEGE_ESCALATION,  # Integer Overflow
    "CWE-120": KillPhase.PRIVILEGE_ESCALATION,  # Buffer Overflow
    "CWE-121": KillPhase.PRIVILEGE_ESCALATION,  # Stack Buffer Overflow
    "CWE-122": KillPhase.PRIVILEGE_ESCALATION,  # Heap Buffer Overflow
    "CWE-125": KillPhase.PRIVILEGE_ESCALATION,  # Out-of-bounds Read
    "CWE-200": KillPhase.CREDENTIAL_ACCESS,     # Exposure of Sensitive Information
    "CWE-352": KillPhase.INITIAL_ACCESS,    # CSRF
    "CWE-434": KillPhase.INITIAL_ACCESS,    # Unrestricted Upload
    "CWE-611": KillPhase.EXECUTION,         # XXE
    "CWE-918": KillPhase.INITIAL_ACCESS,    # SSRF
}


def _infer_from_cwe(cwe_ids: list[str]) -> KillPhase | None:
    for cwe_id in cwe_ids:
        phase = _CWE_TO_PHASE.get(cwe_id)
        if phase is not None:
            return phase
    return None


# ---------------------------------------------------------------------------
# Ransomware hint
# ---------------------------------------------------------------------------

def ransomware_hint(text: str) -> bool:
    return bool(re.search(r"ransomware|crypto.?locker|file.?encrypt", text, re.IGNORECASE))


# ---------------------------------------------------------------------------
# Main classification entry point
# ---------------------------------------------------------------------------

def classify_cve(cve: CveRecord) -> None:
    """Classify a single CVE into a kill-chain phase and ATT&CK techniques.

    Mutates cve.phase, cve.phase_confidence, cve.techniques in place.
    """
    # 1. Try CVSS vector (highest confidence)
    phase = _infer_from_vector(cve.cvss_vector, cve.description)
    if phase is not None:
        cve.phase = phase
        cve.phase_confidence = "HIGH"
    else:
        # 2. Try keywords
        phase = _infer_from_keywords(cve.description)
        if phase is not None:
            cve.phase = phase
            cve.phase_confidence = "MEDIUM"
        else:
            # 3. Try CWE
            phase = _infer_from_cwe(cve.cwe)
            if phase is not None:
                cve.phase = phase
                cve.phase_confidence = "MEDIUM"
            else:
                cve.phase = None
                cve.phase_confidence = "LOW"

    # 4. Match ATT&CK techniques
    cve.techniques = match_techniques(
        cve.description, cve.cvss_vector, cve.cwe, cve.affected_software
    )


def classify_all(cves: list[CveRecord]) -> None:
    """Classify all CVEs in place."""
    for cve in cves:
        classify_cve(cve)
