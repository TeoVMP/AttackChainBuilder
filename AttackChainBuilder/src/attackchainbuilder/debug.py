"""Debug mode output for classification, scoring, and chain construction.

Activated via --debug flag. Prints detailed reasoning for each step.
"""

from __future__ import annotations

from attackchainbuilder.models import (
    PHASE_SHORT,
    AttackChain,
    CveRecord,
    TargetContext,
)
from attackchainbuilder.scoring import p_exploit


def debug_classify(cve: CveRecord) -> str:
    """Return debug output for a single CVE classification."""
    lines: list[str] = []
    lines.append(f"  CVE: {cve.cve_id}")
    lines.append(f"  CVSS: {cve.cvss} | Vector: {cve.cvss_vector or 'N/A'}")
    lines.append(f"  CWE: {', '.join(cve.cwe) or 'N/A'}")
    lines.append(f"  Confidence: {cve.confidence}")
    lines.append(f"  Sources: {', '.join(cve.sources)}")
    lines.append(f"  PoCs: {len(cve.pocs)}")
    lines.append(f"  KEV due: {cve.kev_due_date or 'N/A'}")
    lines.append(f"  Ransomware: {cve.ransomware_use or 'N/A'}")

    # Classification reasoning
    if cve.phase is not None:
        lines.append(f"  → Phase: {cve.phase.name} (confidence: {cve.phase_confidence})")
    else:
        lines.append("  → Phase: UNKNOWN (no classification match)")

    lines.append(f"  → Techniques: {', '.join(cve.techniques) or 'none'}")

    # Exploitability breakdown
    p = p_exploit(cve)
    base = (cve.cvss or 3.0) / 10.0
    lines.append(f"  → p_exploit: {p:.4f} (base={base:.2f}, conf={cve.confidence}, pocs={len(cve.pocs)})")

    # False positives
    from attackchainbuilder.analyzer import detect_false_positives
    fps = detect_false_positives(cve)
    if fps:
        lines.append(f"  → FP flags: {len(fps)}")
        for fp in fps:
            lines.append(f"    [{fp.severity}] {fp.flag}: {fp.detail}")

    return "\n".join(lines)


def debug_classify_all(cves: list[CveRecord]) -> str:
    """Return debug output for all CVE classifications."""
    lines: list[str] = []
    lines.append("CLASSIFICATION DEBUG")
    lines.append("=" * 72)
    for cve in cves:
        lines.append(debug_classify(cve))
        lines.append("-" * 40)
    return "\n".join(lines)


def debug_chain(chain: AttackChain, rank: int) -> str:
    """Return debug output for a single attack chain."""
    lines: list[str] = []
    lines.append(f"Chain #{rank} (Score: {chain.chain_score:.1f})")
    lines.append(f"  Exploitability: {chain.exploitability:.4f}")
    lines.append(f"  Severity mix: {chain.severity_mix:.4f}")
    lines.append(f"  Coverage: {chain.coverage_ratio:.4f}")
    lines.append(f"  Viability: {chain.viability}")
    lines.append(f"  Software link: {chain.software_link_strength:.4f}")

    if chain.fp_flags:
        lines.append(f"  FP flags: {len(chain.fp_flags)}")
        for fp in chain.fp_flags:
            lines.append(f"    [{fp.severity}] {fp.flag}: {fp.detail}")

    lines.append("  Steps:")
    for i, step in enumerate(chain.steps, 1):
        lines.append(f"    {i}. {step.cve_id} ({PHASE_SHORT.get(step.phase, '?')})")
        lines.append(f"       p_exploit={step.p_exploit:.4f} cvss={step.cvss} techs={step.techniques[:3]}")
        if i - 1 < len(chain.details):
            d = chain.details[i - 1]
            lines.append(f"       method={d.exploitation_method or 'N/A'}")
            lines.append(f"       maturity={d.exploit_maturity}")
            lines.append(f"       prereqs={d.prerequisites}")
            lines.append(f"       impact={d.impact_summary or 'N/A'}")
            if d.fp_flags:
                for fp in d.fp_flags:
                    lines.append(f"       FP: [{fp.severity}] {fp.flag}: {fp.detail}")

    return "\n".join(lines)


def debug_chains(chains: list[AttackChain]) -> str:
    """Return debug output for all chains."""
    lines: list[str] = []
    lines.append("CHAIN DEBUG")
    lines.append("=" * 72)
    for i, chain in enumerate(chains, 1):
        lines.append(debug_chain(chain, i))
        lines.append("-" * 40)
    return "\n".join(lines)


def debug_context(context: TargetContext) -> str:
    """Return debug output for the target context."""
    lines: list[str] = []
    lines.append("CONTEXT DEBUG")
    lines.append("=" * 72)
    lines.append(f"  Start phase: {context.start_phase.name if context.start_phase else 'auto'}")
    lines.append(f"  Goal phase: {context.goal_phase.name if context.goal_phase else 'IMPACT'}")
    lines.append(f"  Software: {context.software_tokens or 'any'}")
    lines.append(f"  Version hint: {context.version_hint or 'N/A'}")
    lines.append(f"  Max steps: {context.max_steps}")
    lines.append(f"  Min steps: {context.min_steps}")
    lines.append(f"  Require SW link: {context.require_software_link}")
    return "\n".join(lines)
