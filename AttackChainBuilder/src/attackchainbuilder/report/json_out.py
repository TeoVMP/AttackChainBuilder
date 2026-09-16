"""JSON report writer for attack chains."""

from __future__ import annotations

import json
from pathlib import Path

from attackchainbuilder import __version__
from attackchainbuilder.models import AttackChain


def write(chains: list[AttackChain], path: Path, meta: dict) -> None:
    include_details = meta.get("include_details", False)
    payload = {
        "tool": f"AttackChainBuilder {__version__}",
        "generated_at": meta.get("generated_at"),
        "context": meta.get("context", {}),
        "total_cves": meta.get("total_cves", 0),
        "chains_found": len(chains),
        "chains": [_serialize_chain(c, i, include_details) for i, c in enumerate(chains, 1)],
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _serialize_chain(chain: AttackChain, rank: int, include_details: bool = False) -> dict:
    data = {
        "rank": rank,
        "chain_score": chain.chain_score,
        "exploitability": round(chain.exploitability, 4),
        "severity_mix": round(chain.severity_mix, 4),
        "coverage_ratio": round(chain.coverage_ratio, 4),
        "software_link_strength": round(chain.software_link_strength, 4),
        "viability": chain.viability,
        "fp_flags_count": len(chain.fp_flags),
        "steps": [
            _serialize_step(s, include_details, chain.details[i] if i < len(chain.details) else None)
            for i, s in enumerate(chain.steps)
        ],
    }
    if chain.fp_flags:
        data["false_positive_flags"] = [
            {"flag": f.flag, "severity": f.severity, "detail": f.detail}
            for f in chain.fp_flags
        ]
    return data


def _serialize_step(step, include_details: bool = False, details=None) -> dict:
    data = {
        "cve_id": step.cve_id,
        "phase": step.phase.name,
        "phase_label": step.phase.name.replace("_", " ").title(),
        "tactic_id": step.tactic_id,
        "tactic_name": step.tactic_name,
        "techniques": step.techniques,
        "p_exploit": round(step.p_exploit, 4),
        "cvss": step.cvss,
        "severity": step.severity,
        "software_tokens": step.software_tokens,
    }
    if include_details and details is not None:
        data["exploit_details"] = {
            "attack_vector": details.attack_vector,
            "attack_complexity": details.attack_complexity,
            "privileges_required": details.privileges_required,
            "user_interaction": details.user_interaction,
            "scope": details.scope,
            "impact_confidentiality": details.impact_confidentiality,
            "impact_integrity": details.impact_integrity,
            "impact_availability": details.impact_availability,
            "exploitation_method": details.exploitation_method,
            "prerequisites": details.prerequisites,
            "impact_summary": details.impact_summary,
            "detection_opportunities": details.detection_opportunities,
            "exploit_maturity": details.exploit_maturity,
        }
        data["viability"] = details.exploit_maturity
        if details.fp_flags:
            data["false_positive_flags"] = [
                {"flag": f.flag, "severity": f.severity, "detail": f.detail}
                for f in details.fp_flags
            ]
        if details.sources:
            data["sources"] = details.sources
        if details.pocs:
            data["pocs"] = details.pocs
    return data
