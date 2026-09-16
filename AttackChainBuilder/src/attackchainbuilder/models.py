"""Typed data models for attack chain construction."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class KillPhase(IntEnum):
    """Kill-chain phases ordered by attacker progression (low → high)."""

    INITIAL_ACCESS = 0
    EXECUTION = 1
    PERSISTENCE = 2
    PRIVILEGE_ESCALATION = 3
    CREDENTIAL_ACCESS = 4
    LATERAL_MOVEMENT = 5
    IMPACT = 6


PHASE_LABELS: dict[KillPhase, str] = {
    KillPhase.INITIAL_ACCESS: "Initial Access",
    KillPhase.EXECUTION: "Execution",
    KillPhase.PERSISTENCE: "Persistence",
    KillPhase.PRIVILEGE_ESCALATION: "Privilege Escalation",
    KillPhase.CREDENTIAL_ACCESS: "Credential Access",
    KillPhase.LATERAL_MOVEMENT: "Lateral Movement",
    KillPhase.IMPACT: "Impact",
}

PHASE_SHORT: dict[KillPhase, str] = {
    KillPhase.INITIAL_ACCESS: "INIT-ACCESS",
    KillPhase.EXECUTION: "EXECUTION",
    KillPhase.PERSISTENCE: "PERSIST",
    KillPhase.PRIVILEGE_ESCALATION: "PRIV-ESC",
    KillPhase.CREDENTIAL_ACCESS: "CRED-ACCESS",
    KillPhase.LATERAL_MOVEMENT: "LATERAL",
    KillPhase.IMPACT: "IMPACT",
}


def parse_phase(text: str) -> KillPhase | None:
    """Parse a phase name (case-insensitive, with dashes/underscores)."""
    normalized = text.strip().lower().replace("-", "_").replace(" ", "_")
    for phase in KillPhase:
        if phase.name.lower() == normalized:
            return phase
    aliases = {
        "init": KillPhase.INITIAL_ACCESS,
        "initaccess": KillPhase.INITIAL_ACCESS,
        "priv_esc": KillPhase.PRIVILEGE_ESCALATION,
        "privesc": KillPhase.PRIVILEGE_ESCALATION,
        "priv": KillPhase.PRIVILEGE_ESCALATION,
        "lateral": KillPhase.LATERAL_MOVEMENT,
        "pivot": KillPhase.LATERAL_MOVEMENT,
        "pivoting": KillPhase.LATERAL_MOVEMENT,
        "cred": KillPhase.CREDENTIAL_ACCESS,
    }
    return aliases.get(normalized)


CVSS_SEVERITY_BANDS: list[tuple[float, str]] = [
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.1, "LOW"),
]


def severity_from_cvss(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    for threshold, label in CVSS_SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "NONE"


@dataclass
class CveRecord:
    """A single CVE with all metadata needed for classification and chaining."""

    cve_id: str
    description: str | None = None
    cvss: float | None = None
    cvss_vector: str | None = None
    affected_software: list[str] = field(default_factory=list)
    pocs: list[dict] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    confidence: str = "LOW"
    published: str | None = None
    kev_due_date: str | None = None
    ransomware_use: str | None = None
    cwe: list[str] = field(default_factory=list)

    # Computed by classify
    phase: KillPhase | None = None
    phase_confidence: str = "LOW"
    techniques: list[str] = field(default_factory=list)

    @property
    def severity(self) -> str:
        return severity_from_cvss(self.cvss)

    @property
    def software_tokens(self) -> list[str]:
        """Normalized tokens from affected_software + description."""
        from attackchainbuilder.normalize import tokenize_software

        text = " ".join(self.affected_software) + " " + (self.description or "")
        return tokenize_software(text)


@dataclass
class TargetContext:
    """User-provided context that shapes chain generation."""

    start_phase: KillPhase | None = None
    goal_phase: KillPhase | None = None
    software_tokens: list[str] = field(default_factory=list)
    version_hint: str | None = None
    max_steps: int = 5
    min_steps: int = 2
    require_software_link: bool = False


@dataclass
class ChainStep:
    """One link in an attack chain."""

    cve_id: str
    phase: KillPhase
    tactic_id: str
    tactic_name: str
    techniques: list[str] = field(default_factory=list)
    p_exploit: float = 0.5
    cvss: float | None = None
    severity: str = "UNKNOWN"
    software_tokens: list[str] = field(default_factory=list)
    description: str | None = None


@dataclass
class FalsePositiveFlag:
    """A potential false positive detected in classification or chain."""

    flag: str        # e.g. "theoretical_risk", "classification_mismatch", "vague_description"
    severity: str    # LOW / MEDIUM / HIGH
    detail: str      # Human-readable explanation


@dataclass
class ExploitDetails:
    """Structured technical exploitation details extracted from CVSS + CWE + description."""

    # From CVSS vector
    attack_vector: str | None = None
    attack_complexity: str | None = None
    privileges_required: str | None = None
    user_interaction: str | None = None
    scope: str | None = None
    impact_confidentiality: str | None = None
    impact_integrity: str | None = None
    impact_availability: str | None = None

    # Derived
    exploitation_method: str | None = None
    prerequisites: list[str] = field(default_factory=list)
    impact_summary: str | None = None
    detection_opportunities: list[str] = field(default_factory=list)

    # Sources & PoCs
    sources: list[dict] = field(default_factory=list)
    pocs: list[dict] = field(default_factory=list)
    exploit_maturity: str = "unknown"  # weaponized / poc / theoretical

    # False positives
    fp_flags: list[FalsePositiveFlag] = field(default_factory=list)


@dataclass
class AttackChain:
    """A complete attack chain with scoring."""

    steps: list[ChainStep] = field(default_factory=list)
    exploitability: float = 0.0
    severity_mix: float = 0.0
    chain_score: float = 0.0
    coverage_ratio: float = 0.0
    software_link_strength: float = 0.0
    viability: str = "UNKNOWN"  # HIGH / MEDIUM / LOW
    details: list[ExploitDetails] = field(default_factory=list)
    fp_flags: list[FalsePositiveFlag] = field(default_factory=list)
