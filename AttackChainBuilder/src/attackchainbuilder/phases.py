"""Kill-chain phase ↔ MITRE ATT&CK tactic mapping."""

from __future__ import annotations

from attackchainbuilder.models import KillPhase

# ATT&CK Enterprise tactics mapped to kill-chain phases
PHASE_TO_TACTIC: dict[KillPhase, tuple[str, str]] = {
    KillPhase.INITIAL_ACCESS: ("TA0001", "Initial Access"),
    KillPhase.EXECUTION: ("TA0002", "Execution"),
    KillPhase.PERSISTENCE: ("TA0003", "Persistence"),
    KillPhase.PRIVILEGE_ESCALATION: ("TA0004", "Privilege Escalation"),
    KillPhase.CREDENTIAL_ACCESS: ("TA0006", "Credential Access"),
    KillPhase.LATERAL_MOVEMENT: ("TA0008", "Lateral Movement"),
    KillPhase.IMPACT: ("TA0040", "Impact"),
}

TACTIC_TO_PHASE: dict[str, KillPhase] = {
    tactic_id: phase for phase, (tactic_id, _) in PHASE_TO_TACTIC.items()
}


def tactic_for(phase: KillPhase) -> tuple[str, str]:
    return PHASE_TO_TACTIC[phase]


def phase_for_tactic(tactic_id: str) -> KillPhase | None:
    return TACTIC_TO_PHASE.get(tactic_id)
