"""MITRE ATT&CK technique catalog (curated subset for CVE classification).

Each technique includes:
- id: ATT&CK technique ID (e.g. T1190)
- name: human-readable name
- primary_tactic: the main tactic phase
- keywords: regex-ready strings that hint at this technique in CVE descriptions
"""

from __future__ import annotations

from dataclasses import dataclass

from attackchainbuilder.models import KillPhase


@dataclass
class TechniqueDef:
    id: str
    name: str
    primary_tactic: KillPhase
    keywords: list[str]


TECHNIQUES: dict[str, TechniqueDef] = {
    "T1190": TechniqueDef(
        id="T1190",
        name="Exploit Public-Facing Application",
        primary_tactic=KillPhase.INITIAL_ACCESS,
        keywords=[
            "public.facing",
            "web server",
            "web application",
            "http",
            "apache",
            "nginx",
            "iis",
            "tomcat",
            "weblogic",
            "confluence",
            "jenkins",
            "wordpress",
            "drupal",
            "joomla",
            "exchange",
            "owa",
            "citrix",
            "fortinet",
            "vpn",
            "firewall",
        ],
    ),
    "T1203": TechniqueDef(
        id="T1203",
        name="Exploitation for Client Execution",
        primary_tactic=KillPhase.EXECUTION,
        keywords=[
            "client.side",
            "browser",
            "office",
            "word",
            "excel",
            "pdf",
            "media.player",
            "activex",
            "javascript",
            "xss",
            "cross.site scripting",
        ],
    ),
    "T1059": TechniqueDef(
        id="T1059",
        name="Command and Scripting Interpreter",
        primary_tactic=KillPhase.EXECUTION,
        keywords=[
            "command injection",
            "os command",
            "code execution",
            "rce",
            "remote code execution",
            "arbitrary command",
            "shell injection",
            "deserialization",
            "unsafe deserialization",
            "eval injection",
            "template injection",
            "expression language",
            "ognl",
            "spel",
            "jndi",
            "log4j",
            "log4shell",
        ],
    ),
    "T1068": TechniqueDef(
        id="T1068",
        name="Exploitation for Privilege Escalation",
        primary_tactic=KillPhase.PRIVILEGE_ESCALATION,
        keywords=[
            "privilege escalation",
            "local privilege",
            "lpe",
            "escalat",
            "root",
            "kernel",
            "sudo",
            "setuid",
            "buffer overflow",
            "heap overflow",
            "stack overflow",
            "use.after.free",
            "race condition",
            "type confusion",
            "integer overflow",
            "memory corruption",
            "pkexec",
            "polkit",
            "sam edit",
            "baron samedit",
        ],
    ),
    "T1078": TechniqueDef(
        id="T1078",
        name="Valid Accounts",
        primary_tactic=KillPhase.INITIAL_ACCESS,
        keywords=[
            "authentication bypass",
            "auth bypass",
            "default credentials",
            "default password",
            "hardcoded password",
            "hardcoded credential",
            "credential stuffing",
            "brute force",
            "password spray",
            "account takeover",
        ],
    ),
    "T1210": TechniqueDef(
        id="T1210",
        name="Exploitation of Remote Services",
        primary_tactic=KillPhase.LATERAL_MOVEMENT,
        keywords=[
            "lateral",
            "pivot",
            "remote service",
            "smb",
            "rdp",
            "ssh",
            "winrm",
            "wmi",
            "dcom",
            "eternalblue",
            "bluekeep",
            "smbv",
            "worm",
            "spread",
            "self.propagat",
            "network propagation",
        ],
    ),
    "T1212": TechniqueDef(
        id="T1212",
        name="Exploitation for Credential Access",
        primary_tactic=KillPhase.CREDENTIAL_ACCESS,
        keywords=[
            "credential",
            "password",
            "hash dump",
            "lsass",
            "mimikatz",
            "token theft",
            "kerberos",
            "ntlm",
            "sam database",
            "credential dump",
            "password steal",
            "session hijack",
        ],
    ),
    "T1003": TechniqueDef(
        id="T1003",
        name="OS Credential Dumping",
        primary_tactic=KillPhase.CREDENTIAL_ACCESS,
        keywords=[
            "credential dump",
            "lsass",
            "mimikatz",
            "hashdump",
            "ntds.dit",
            "sam file",
            "dpapi",
            "kerberoast",
            "asreproast",
            "dcsync",
        ],
    ),
    "T1505.003": TechniqueDef(
        id="T1505.003",
        name="Server Software Component: Web Shell",
        primary_tactic=KillPhase.PERSISTENCE,
        keywords=[
            "webshell",
            "web shell",
            "backdoor",
            "web.backdoor",
            "persistent backdoor",
        ],
    ),
    "T1053": TechniqueDef(
        id="T1053",
        name="Scheduled Task/Job",
        primary_tactic=KillPhase.PERSISTENCE,
        keywords=[
            "scheduled task",
            "cron",
            "at job",
            "systemd timer",
            "startup",
            "autostart",
            "boot persistence",
        ],
    ),
    "T1543": TechniqueDef(
        id="T1543",
        name="Create or Modify System Process",
        primary_tactic=KillPhase.PERSISTENCE,
        keywords=[
            "systemd service",
            "init.d",
            "launchd",
            "windows service",
            "service creation",
            "process injection",
            "dll injection",
            "dll side.loading",
            "hijack",
        ],
    ),
    "T1548": TechniqueDef(
        id="T1548",
        name="Abuse Elevation Control Mechanism",
        primary_tactic=KillPhase.PRIVILEGE_ESCALATION,
        keywords=[
            "uac bypass",
            "setuid",
            "setgid",
            "capabilities",
            "sudoers",
            "suid",
            "sgid",
        ],
    ),
    "T1486": TechniqueDef(
        id="T1486",
        name="Data Encrypted for Impact",
        primary_tactic=KillPhase.IMPACT,
        keywords=[
            "ransomware",
            "encrypt",
            "data encrypted",
            "crypto.locker",
            "file encrypt",
            "ransom",
        ],
    ),
    "T1485": TechniqueDef(
        id="T1485",
        name="Data Destruction",
        primary_tactic=KillPhase.IMPACT,
        keywords=[
            "data destruction",
            "wipe",
            "delete data",
            "destructive",
            "shredder",
            "data loss",
        ],
    ),
    "T1489": TechniqueDef(
        id="T1489",
        name="Service Stop",
        primary_tactic=KillPhase.IMPACT,
        keywords=[
            "service stop",
            "denial of service",
            "dos",
            "ddos",
            "crash",
            "availability",
            "resource exhaustion",
        ],
    ),
    "T1490": TechniqueDef(
        id="T1490",
        name="Inhibit System Recovery",
        primary_tactic=KillPhase.IMPACT,
        keywords=[
            "backup delet",
            "shadow copy",
            "recovery inhibit",
            "system restore",
            "boot destroy",
        ],
    ),
    "T1557": TechniqueDef(
        id="T1557",
        name="Adversary-in-the-Middle",
        primary_tactic=KillPhase.CREDENTIAL_ACCESS,
        keywords=[
            "mitm",
            "man.in.the.middle",
            "arp spoof",
            "dns poison",
            "traffic intercept",
            "ssl strip",
        ],
    ),
    "T1021": TechniqueDef(
        id="T1021",
        name="Remote Services",
        primary_tactic=KillPhase.LATERAL_MOVEMENT,
        keywords=[
            "remote desktop",
            "rdp",
            "ssh",
            "smb",
            "winrm",
            "wmi",
            "remote access",
            "remote service",
            "telnet",
            "vnc",
        ],
    ),
    "T1110": TechniqueDef(
        id="T1110",
        name="Brute Force",
        primary_tactic=KillPhase.CREDENTIAL_ACCESS,
        keywords=[
            "brute.force",
            "password guess",
            "credential stuffing",
            "password spray",
            "online attack",
            "dictionary attack",
        ],
    ),
    "T1134": TechniqueDef(
        id="T1134",
        name="Access Token Manipulation",
        primary_tactic=KillPhase.PRIVILEGE_ESCALATION,
        keywords=[
            "token manipulation",
            "token impersonat",
            "access token",
            "sid history",
            "token steal",
        ],
    ),
    "T1552": TechniqueDef(
        id="T1552",
        name="Unsecured Credentials",
        primary_tactic=KillPhase.CREDENTIAL_ACCESS,
        keywords=[
            "unsecured credential",
            "plaintext password",
            "config file credential",
            "credential file",
            "password file",
            "exposed secret",
        ],
    ),
}


def match_techniques(
    description: str | None,
    cvss_vector: str | None,
    cwe: list[str],
    software: list[str],
) -> list[str]:
    """Return matching ATT&CK technique IDs based on keywords and context."""
    if not description:
        return []

    text = description.lower() + " " + " ".join(software).lower()
    matches: list[str] = []

    for tech_id, tech in TECHNIQUES.items():
        score = 0
        for kw in tech.keywords:
            if kw.lower() in text:
                score += 1
        if score > 0:
            matches.append(tech_id)

    # CWE-based hints
    cwe_hints = {
        "CWE-89": "T1190",   # SQL Injection → web app exploit
        "CWE-78": "T1059",   # OS Command Injection
        "CWE-79": "T1203",   # XSS → client execution
        "CWE-94": "T1059",   # Code Injection
        "CWE-269": "T1068",  # Improper Privilege Management
        "CWE-287": "T1078",  # Improper Authentication
        "CWE-502": "T1059",  # Deserialization
        "CWE-22": "T1190",   # Path Traversal (often web)
        "CWE-787": "T1068",  # Out-of-bounds Write (often LPE)
        "CWE-416": "T1068",  # Use After Free (often LPE)
        "CWE-190": "T1068",  # Integer Overflow
        "CWE-120": "T1068",  # Buffer Overflow
    }
    for cwe_id in cwe:
        mapped = cwe_hints.get(cwe_id)
        if mapped and mapped not in matches:
            matches.append(mapped)

    return matches
