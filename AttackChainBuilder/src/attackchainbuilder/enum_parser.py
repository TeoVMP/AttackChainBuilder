"""Parse enumeration data from free-form text files.

Supports: nmap, curl headers, whatweb, wappalyzer, config files,
and any free-form text. Extracts software names, versions, ports,
and attack context.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class EnumResult:
    """Parsed enumeration data."""

    software: list[dict[str, str]] = field(default_factory=list)  # [{name, version, source}]
    ports: list[dict[str, str]] = field(default_factory=list)     # [{port, service, version}]
    urls: list[str] = field(default_factory=list)
    context: str = ""
    raw_text: str = ""
    attack_phase: str = ""  # initial-access, foothold, privesc, lateral, etc.


# Nmap patterns: 80/tcp open http Apache httpd 2.4.49
_NMAP_RE = re.compile(
    r"(\d+)/(?:tcp|udp)\s+open\s+(\S+)\s+(.+?)(?:\s*$)",
    re.MULTILINE,
)

# Nmap service version: Apache httpd 2.4.49, OpenSSH 8.2p1
_NMAP_VERSION_RE = re.compile(
    r"([A-Za-z][A-Za-z0-9._-]+)\s+(?:httpd|server|daemon|service)?\s*(\d+\.\d+[\.\d]*)",
    re.IGNORECASE,
)

# Server header: Server: Apache/2.4.49 (Ubuntu)
_HEADER_RE = re.compile(
    r"(?:Server|X-Powered-By|X-Generator|X-CMS):\s*(.+?)(?:\r?\n|$)",
    re.IGNORECASE,
)

# Slash format: Apache/2.4.49, OpenSSL/1.1.1k, PHP/7.4.3
_SLASH_VERSION_RE = re.compile(
    r"([A-Za-z][A-Za-z0-9._-]+)/(\d+\.\d+[\.\d]*[a-z0-9.]*)",
    re.IGNORECASE,
)

# Space format: Apache 2.4.49, OpenSSL 1.1.1k
_SPACE_VERSION_RE = re.compile(
    r"\b([A-Za-z][A-Za-z0-9._-]{2,})\s+(\d+\.\d+[\.\d]*[a-z0-9.]*)\b",
    re.IGNORECASE,
)

# Whatweb/Wappalyzer style: [Apache 2.4.49], [OpenSSL 1.1.1k]
_BRACKET_RE = re.compile(
    r"\[([A-Za-z][A-Za-z0-9._-]+)\s+(\d+\.\d+[\.\d]*[a-z0-9.]*)\]",
    re.IGNORECASE,
)

# URL patterns
_URL_RE = re.compile(
    r"https?://[^\s\"'<>]+",
    re.IGNORECASE,
)

# Attack phase detection
_PHASE_PATTERNS = {
    "initial-access": re.compile(
        r"initial\s*access|recon|scanning|enumerat|nmap|nikto|gobuster|dirb|ffuf|wfuzz|whatweb",
        re.IGNORECASE,
    ),
    "foothold": re.compile(
        r"foothold|shell|reverse\s*shell|webshell|upload|exploit|rce|command\s*injection|sqli|xss",
        re.IGNORECASE,
    ),
    "privesc": re.compile(
        r"priv(ilege)?\s*escalat|linpeas|winpeas|sudo\s*-l|suid|cron|kernel|dirty.?cow",
        re.IGNORECASE,
    ),
    "lateral": re.compile(
        r"lateral|pivot|pass.?the.?hash|psexec|wmiexec|smb|rdp|ssh\s*tunnel",
        re.IGNORECASE,
    ),
    "impact": re.compile(
        r"impact|root|admin|flag|proof|loot|dump|exfiltrat|ransomware",
        re.IGNORECASE,
    ),
}

# Known software aliases
_SW_ALIASES = {
    "httpd": "apache",
    "apache2": "apache",
    "http": "apache",
    "https": "apache",
    "ssh": "openssh",
    "smtp": "postfix",
    "ftp": "vsftpd",
    "dns": "bind",
    "mysql": "mysql",
    "mariadb": "mysql",
    "postgres": "postgresql",
    "php": "php",
    "iis": "microsoft-iis",
    "microsoft-iis": "microsoft-iis",
    "tomcat": "apache-tomcat",
    "nginx": "nginx",
    "vsftpd": "vsftpd",
    "proftpd": "proftpd",
    "samba": "samba",
    "smb": "samba",
    "cups": "cups",
    "redis": "redis",
    "mongo": "mongodb",
    "elasticsearch": "elasticsearch",
    "jenkins": "jenkins",
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
    "confluence": "atlassian-confluence",
    "jira": "atlassian-jira",
}

# Version cleaning
def _clean_version(v: str) -> str:
    v = v.strip().rstrip(".")
    if len(v) > 20:
        v = v[:20]
    return v


def _normalize_software(name: str) -> str:
    name = name.strip().lower()
    name = re.sub(r"[^a-z0-9._-]", "", name)
    return _SW_ALIASES.get(name, name)


def parse_enum_file(path: str) -> EnumResult:
    """Parse an enumeration file and extract software, ports, context."""
    from pathlib import Path

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Enum file not found: {path}")

    text = p.read_text(encoding="utf-8", errors="ignore")
    return parse_enum_text(text)


def parse_enum_text(text: str) -> EnumResult:
    """Parse enumeration text and extract structured data."""
    result = EnumResult(raw_text=text)
    seen_sw: set[str] = set()

    # 1. Nmap port/service detection
    for m in _NMAP_RE.finditer(text):
        port, service, version_info = m.groups()
        result.ports.append({
            "port": port,
            "service": service,
            "version": version_info.strip(),
        })
        # Extract software from version info
        for vm in _NMAP_VERSION_RE.finditer(version_info):
            sw_name = _normalize_software(vm.group(1))
            sw_ver = _clean_version(vm.group(2))
            key = f"{sw_name} {sw_ver}"
            if key not in seen_sw:
                seen_sw.add(key)
                result.software.append({"name": sw_name, "version": sw_ver, "source": "nmap"})

    # 2. HTTP headers (Server, X-Powered-By, etc.)
    for m in _HEADER_RE.finditer(text):
        header_val = m.group(1).strip()
        for vm in _SLASH_VERSION_RE.finditer(header_val):
            sw_name = _normalize_software(vm.group(1))
            sw_ver = _clean_version(vm.group(2))
            key = f"{sw_name} {sw_ver}"
            if key not in seen_sw:
                seen_sw.add(key)
                result.software.append({"name": sw_name, "version": sw_ver, "source": "header"})

    # 3. Slash format (Apache/2.4.49, OpenSSL/1.1.1k)
    for m in _SLASH_VERSION_RE.finditer(text):
        sw_name = _normalize_software(m.group(1))
        sw_ver = _clean_version(m.group(2))
        key = f"{sw_name} {sw_ver}"
        if key not in seen_sw:
            seen_sw.add(key)
            result.software.append({"name": sw_name, "version": sw_ver, "source": "text"})

    # 4. Space format (Apache 2.4.49, OpenSSL 1.1.1k)
    for m in _SPACE_VERSION_RE.finditer(text):
        sw_name = _normalize_software(m.group(1))
        sw_ver = _clean_version(m.group(2))
        key = f"{sw_name} {sw_ver}"
        if key not in seen_sw:
            seen_sw.add(key)
            result.software.append({"name": sw_name, "version": sw_ver, "source": "text"})

    # 5. Bracket format [Apache 2.4.49]
    for m in _BRACKET_RE.finditer(text):
        sw_name = _normalize_software(m.group(1))
        sw_ver = _clean_version(m.group(2))
        key = f"{sw_name} {sw_ver}"
        if key not in seen_sw:
            seen_sw.add(key)
            result.software.append({"name": sw_name, "version": sw_ver, "source": "whatweb"})

    # 6. URLs
    result.urls = list(set(_URL_RE.findall(text)))

    # 7. Detect attack phase
    for phase, pattern in _PHASE_PATTERNS.items():
        if pattern.search(text):
            result.attack_phase = phase
            break

    # 8. Build context summary
    ctx_parts = []
    if result.ports:
        ports_str = ", ".join(f"{p['port']}/{p['service']}" for p in result.ports[:5])
        ctx_parts.append(f"Open ports: {ports_str}")
    if result.attack_phase:
        ctx_parts.append(f"Attack phase: {result.attack_phase}")
    if result.urls:
        ctx_parts.append(f"URLs found: {len(result.urls)}")

    # Detect authentication hints
    if re.search(r"no\s*auth|unauth|anonymous|default\s*(cred|pass)", text, re.IGNORECASE):
        ctx_parts.append("No authentication required")
    if re.search(r"login|auth|password|credential", text, re.IGNORECASE):
        ctx_parts.append("Authentication present")
    if re.search(r"internal|localhost|127\.0\.0\.1|10\.\d|192\.168", text, re.IGNORECASE):
        ctx_parts.append("Internal network")
    if re.search(r"internet|external|public", text, re.IGNORECASE):
        ctx_parts.append("External/public")

    result.context = "; ".join(ctx_parts) if ctx_parts else "Enumeration data provided"

    return result


def filter_relevant_cves(
    cves: list,
    software: list[dict[str, str]],
    max_cves: int = 15,
) -> list:
    """Filter CVEs relevant to the detected software.

    Returns top CVEs sorted by relevance (CVSS, confidence, PoCs).
    """
    if not software:
        return cves[:max_cves]

    # Build search tokens from software names
    sw_tokens = set()
    for sw in software:
        name = sw.get("name", "").lower()
        if name:
            sw_tokens.add(name)
            # Add partial matches (e.g., "apache" matches "apache httpd")
            parts = name.replace("-", " ").replace(".", " ").split()
            sw_tokens.update(parts)

    # Score each CVE by relevance
    scored: list[tuple[float, object]] = []
    for cve in cves:
        score = 0.0

        # Check affected_software
        affected = " ".join(cve.affected_software).lower()
        for token in sw_tokens:
            if token in affected:
                score += 10.0

        # Check description
        desc = (cve.description or "").lower()
        for token in sw_tokens:
            if token in desc:
                score += 5.0

        # Bonus for high CVSS
        if cve.cvss:
            score += cve.cvss * 0.5

        # Bonus for PoCs
        score += min(3.0, len(cve.pocs) * 0.5)

        # Bonus for KEV
        if "cisa-kev" in cve.sources:
            score += 5.0

        # Bonus for high confidence
        if cve.confidence == "HIGH":
            score += 2.0

        scored.append((score, cve))

    # Sort by score descending, return top N
    scored.sort(key=lambda x: x[0], reverse=True)
    return [cve for _, cve in scored[:max_cves]]
