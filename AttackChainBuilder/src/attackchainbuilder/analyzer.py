"""Viability analysis and false positive detection for attack chains.

Analyzes each CVE and chain for:
- Exploit viability (is there a real, usable exploit?)
- False positive flags (classification mismatches, theoretical risks, etc.)
- Chain-level viability score
"""

from __future__ import annotations

from attackchainbuilder.details import extract_details
from attackchainbuilder.models import (
    AttackChain,
    CveRecord,
    ExploitDetails,
    FalsePositiveFlag,
)


def detect_false_positives(cve: CveRecord) -> list[FalsePositiveFlag]:
    """Detect potential false positives in a CVE's classification."""
    flags: list[FalsePositiveFlag] = []

    # 1. High CVSS but no PoCs → theoretical risk
    if (cve.cvss or 0) >= 9.0 and not cve.pocs:
        flags.append(FalsePositiveFlag(
            flag="theoretical_risk",
            severity="MEDIUM",
            detail=f"CVSS {cve.cvss} but no PoC/exploit references found. May be theoretical.",
        ))

    # 2. Low classification confidence
    if cve.phase_confidence == "LOW":
        flags.append(FalsePositiveFlag(
            flag="uncertain_classification",
            severity="HIGH",
            detail="Phase classification has LOW confidence (no vector/keyword/CWE match).",
        ))

    # 3. Classification mismatch: vector says one thing, keywords another
    if cve.cvss_vector and cve.description:
        from attackchainbuilder.classify import _infer_from_keywords, _infer_from_vector
        vector_phase = _infer_from_vector(cve.cvss_vector, cve.description)
        keyword_phase = _infer_from_keywords(cve.description)
        if (
            vector_phase is not None
            and keyword_phase is not None
            and vector_phase != keyword_phase
        ):
            flags.append(FalsePositiveFlag(
                flag="classification_mismatch",
                severity="MEDIUM",
                detail=(
                    f"CVSS vector suggests {vector_phase.name} "
                    f"but keywords suggest {keyword_phase.name}."
                ),
            ))

    # 4. Old CVE without KEV → likely patched
    if cve.published:
        try:
            year = int(cve.published[:4])
            if year < 2020 and "cisa-kev" not in cve.sources:
                flags.append(FalsePositiveFlag(
                    flag="likely_patched",
                    severity="LOW",
                    detail=f"Published in {year} and not in CISA KEV. Likely patched in current versions.",
                ))
        except (ValueError, IndexError):
            pass

    # 5. Vague description
    desc = (cve.description or "").lower()
    if len(desc) < 50:
        flags.append(FalsePositiveFlag(
            flag="vague_description",
            severity="LOW",
            detail="Description is very short (<50 chars). Classification may be unreliable.",
        ))

    # 6. Unverified ransomware claim
    if (cve.ransomware_use or "").lower() == "known":
        has_ransomware_poc = any(
            "ransomware" in (p.get("url", "") + p.get("kind", "")).lower()
            for p in cve.pocs
        )
        if not has_ransomware_poc and "cisa-kev" not in cve.sources:
            flags.append(FalsePositiveFlag(
                flag="unverified_ransomware",
                severity="MEDIUM",
                detail="Ransomware use claimed but no ransomware-specific PoC and not in CISA KEV.",
            ))

    # 7. No affected software
    if not cve.affected_software:
        flags.append(FalsePositiveFlag(
            flag="no_software_info",
            severity="LOW",
            detail="No affected software listed. Target identification is uncertain.",
        ))

    return flags


def assess_viability(cve: CveRecord, details: ExploitDetails) -> str:
    """Assess exploitation viability for a single CVE.

    Returns: HIGH / MEDIUM / LOW
    """
    score = 0

    # Maturity
    if details.exploit_maturity == "weaponized":
        score += 3
    elif details.exploit_maturity == "poc":
        score += 2
    else:
        score += 0

    # KEV presence
    if "cisa-kev" in cve.sources:
        score += 3

    # Confidence
    if cve.confidence == "HIGH":
        score += 2
    elif cve.confidence == "MEDIUM":
        score += 1

    # PoC count
    score += min(2, len(cve.pocs))

    # Ransomware
    if (cve.ransomware_use or "").lower() == "known":
        score += 1

    # FP flags penalty
    high_fps = sum(1 for f in details.fp_flags if f.severity == "HIGH")
    score -= high_fps * 2

    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"


def analyze_chain(chain: AttackChain, cves: list[CveRecord]) -> None:
    """Analyze an entire attack chain for viability and false positives.

    Mutates chain.viability, chain.details, chain.fp_flags in place.
    """
    cve_map = {c.cve_id: c for c in cves}

    chain_details: list[ExploitDetails] = []
    chain_fps: list[FalsePositiveFlag] = []
    viabilities: list[str] = []

    for step in chain.steps:
        cve = cve_map.get(step.cve_id)
        if cve is None:
            continue

        # Extract details
        details = extract_details(cve)

        # Detect false positives
        fps = detect_false_positives(cve)
        details.fp_flags = fps
        chain_fps.extend(fps)

        # Assess viability
        viability = assess_viability(cve, details)
        viabilities.append(viability)

        chain_details.append(details)

    chain.details = chain_details
    chain.fp_flags = chain_fps

    # Chain viability = worst step viability
    if "LOW" in viabilities:
        chain.viability = "LOW"
    elif "MEDIUM" in viabilities:
        chain.viability = "MEDIUM"
    elif viabilities:
        chain.viability = "HIGH"
    else:
        chain.viability = "UNKNOWN"


def analyze_all_chains(chains: list[AttackChain], cves: list[CveRecord]) -> None:
    """Analyze all chains in place."""
    for chain in chains:
        analyze_chain(chain, cves)


def get_cve_fp_summary(cves: list[CveRecord]) -> dict[str, list[FalsePositiveFlag]]:
    """Return a summary of false positive flags per CVE."""
    summary: dict[str, list[FalsePositiveFlag]] = {}
    for cve in cves:
        fps = detect_false_positives(cve)
        if fps:
            summary[cve.cve_id] = fps
    return summary
