"""Software name normalization for matching across CVEs."""

from __future__ import annotations

import re

# Synonyms: variant → canonical token
SYNONYMS: dict[str, str] = {
    "httpd": "apache",
    "http server": "apache",
    "apache2": "apache",
    "log4j": "log4j",
    "log4j2": "log4j",
    "log4shell": "log4j",
    "win": "windows",
    "win10": "windows",
    "win11": "windows",
    "winserver": "windows",
    "server": "server",
    "exchange": "exchange",
    "owa": "exchange",
    "outlook web": "exchange",
    "iis": "iis",
    "tomcat": "tomcat",
    "weblogic": "weblogic",
    "confluence": "confluence",
    "jenkins": "jenkins",
    "wordpress": "wordpress",
    "wp": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
    "nginx": "nginx",
    "openssl": "openssl",
    "openssh": "openssh",
    "ssh": "ssh",
    "rdp": "rdp",
    "smb": "smb",
    "samba": "smb",
    "cifs": "smb",
    "ftp": "ftp",
    "dns": "dns",
    "bind": "dns",
    "postfix": "postfix",
    "sendmail": "sendmail",
    "mysql": "mysql",
    "mariadb": "mysql",
    "postgres": "postgresql",
    "postgresql": "postgresql",
    "mongo": "mongodb",
    "mongodb": "mongodb",
    "redis": "redis",
    "elasticsearch": "elasticsearch",
    "elastic": "elasticsearch",
    "kibana": "kibana",
    "grafana": "grafana",
    "php": "php",
    "python": "python",
    "java": "java",
    "spring": "spring",
    "springframework": "spring",
    "struts": "struts",
    "jboss": "jboss",
    "wildfly": "jboss",
    "glassfish": "glassfish",
    "sudo": "sudo",
    "polkit": "polkit",
    "pkexec": "polkit",
    "systemd": "systemd",
    "linux": "linux",
    "kernel": "linux",
    "xen": "xen",
    "vmware": "vmware",
    "esxi": "vmware",
    "vcenter": "vmware",
    "citrix": "citrix",
    "netscaler": "citrix",
    "fortinet": "fortinet",
    "fortigate": "fortinet",
    "fortios": "fortinet",
    "paloalto": "paloalto",
    "pan-os": "paloalto",
    "panos": "paloalto",
    "sonicwall": "sonicwall",
    "mikrotik": "mikrotik",
    "routeros": "mikrotik",
    "oracle": "oracle",
    "apache struts": "struts",
    "apache tomcat": "tomcat",
    "xz": "xz",
    "xzutils": "xz",
    "xz utils": "xz",
    "liblzma": "xz",
    "atlassian": "atlassian",
    "jira": "jira",
    "bitbucket": "bitbucket",
    "cisco": "cisco",
    "ios": "cisco-ios",
    "nx-os": "cisco-nxos",
}

# Token separator pattern
_TOKEN_SEP = re.compile(r"[\s/:;,.()+\-]+")

# Words too common to be useful tokens
_STOPWORDS = frozenset({
    "the", "a", "an", "in", "on", "for", "of", "and", "or", "to", "is", "it",
    "with", "from", "by", "as", "at", "be", "this", "that", "are", "was",
    "were", "been", "has", "have", "had", "do", "does", "did", "but", "not",
    "no", "can", "will", "if", "may", "up", "all", "one", "two", "new", "old",
    "v", "vs", "via", "using", "used", "use", "allows", "allow", "could",
})


def tokenize_software(text: str) -> list[str]:
    """Extract and normalize software tokens from a text string.

    Returns deduplicated canonical tokens (order preserved).
    """
    if not text:
        return []

    raw_tokens = _TOKEN_SEP.split(text.lower())
    result: list[str] = []
    seen: set[str] = set()

    for token in raw_tokens:
        token = token.strip()
        if not token or token in _STOPWORDS or len(token) < 2:
            continue
        canonical = SYNONYMS.get(token, token)
        if canonical not in seen:
            seen.add(canonical)
            result.append(canonical)

    return result


def software_overlap(tokens_a: list[str], tokens_b: list[str]) -> float:
    """Compute the overlap ratio between two token sets.

    Returns 0.0 if either set is empty, otherwise |A∩B| / min(|A|, |B|).
    """
    if not tokens_a or not tokens_b:
        return 0.0
    set_a = set(tokens_a)
    set_b = set(tokens_b)
    intersection = set_a & set_b
    return len(intersection) / min(len(set_a), len(set_b))
