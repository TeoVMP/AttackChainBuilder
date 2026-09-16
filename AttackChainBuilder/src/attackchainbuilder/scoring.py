"""Scoring engine: exploitability product × severity mix.

Two independent metrics combined via geometric mean:
- exploitability: ∏ p_exploit(step) — probability that all steps are exploitable
- severity_mix: weighted combination of CVSS, coverage, confidence, PoCs, KEV/ransomware

chain_score = 100 × √(exploitability × severity_mix)
"""

from __future__ import annotations

from attackchainbuilder.models import AttackChain, CveRecord, TargetContext

CONFIDENCE_MULT: dict[str, float] = {
    "HIGH": 1.0,
    "MEDIUM": 0.85,
    "LOW": 0.7,
}


def p_exploit(cve: CveRecord) -> float:
    """Compute per-step exploitability probability for a single CVE.

    Factors: CVSS score, confidence, PoC availability, KEV/ransomware presence.
    Returns value clamped to [0.05, 0.98].
    """
    base = (cve.cvss or 3.0) / 10.0
    conf_mult = CONFIDENCE_MULT.get(cve.confidence, 0.7)
    poc_bonus = min(0.2, 0.05 * len(cve.pocs))
    kev_bonus = 0.15 if "cisa-kev" in cve.sources else 0.0
    ransomware_bonus = 0.1 if (cve.ransomware_use or "").lower() == "known" else 0.0

    p = base * conf_mult + poc_bonus + kev_bonus + ransomware_bonus
    return max(0.05, min(0.98, p))


def compute_chain_scores(
    chain: AttackChain,
    context: TargetContext,
    context_tokens: set[str],
) -> None:
    """Compute all scores for an attack chain in place."""
    if not chain.steps:
        return

    # 1. Exploitability = ∏ p_exploit
    product = 1.0
    for step in chain.steps:
        product *= step.p_exploit
    chain.exploitability = product

    # 2. Severity mix (weighted combination, normalized to [0, 1])
    cvss_values = [s.cvss for s in chain.steps if s.cvss is not None]
    mean_cvss = (sum(cvss_values) / len(cvss_values) / 10.0) if cvss_values else 0.3

    # Phase coverage: distinct phases spanned / total possible (7 phases)
    distinct_phases = len({s.phase for s in chain.steps})
    coverage = distinct_phases / 7.0

    # Confidence score — use p_exploit as proxy (higher ≈ more confident)
    mean_conf = sum(s.p_exploit for s in chain.steps) / len(chain.steps)

    # PoC richness: total PoCs across steps / (steps * 3) capped at 1.0
    # We don't have PoC count in ChainStep, but p_exploit already accounts for it.
    # Use a simpler metric: steps with high p_exploit (>0.7) ratio
    high_exploit_ratio = sum(1 for s in chain.steps if s.p_exploit > 0.7) / len(chain.steps)

    # Software link strength
    if context_tokens:
        matching = sum(
            1 for s in chain.steps
            if set(s.software_tokens) & context_tokens
        )
        chain.software_link_strength = matching / len(chain.steps)
    else:
        chain.software_link_strength = 0.5  # neutral

    # Ransomware/KEV bonus
    has_ransomware = any(
        "ransomware" in (s.description or "").lower() for s in chain.steps
    )
    has_kev = any(s.p_exploit > 0.85 for s in chain.steps)  # proxy for KEV HIGH
    bonus = 0.1 if has_ransomware else 0.0
    bonus += 0.05 if has_kev else 0.0

    # Weighted combination
    chain.severity_mix = min(1.0, (
        0.40 * mean_cvss
        + 0.25 * coverage
        + 0.20 * mean_conf
        + 0.15 * high_exploit_ratio
        + bonus
    ))

    chain.coverage_ratio = coverage

    # 3. Chain score = 100 × √(exploitability × severity_mix)
    chain.chain_score = round(100.0 * (chain.exploitability * chain.severity_mix) ** 0.5, 1)
