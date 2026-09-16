"""Markdown report writer for attack chains."""

from __future__ import annotations

from pathlib import Path

from attackchainbuilder import __version__
from attackchainbuilder.models import PHASE_SHORT, AttackChain


def _escape(text: str | None) -> str:
    return (text or "").replace("|", "\\|").replace("\n", " ").strip()


def write(chains: list[AttackChain], path: Path, meta: dict) -> None:
    include_details = meta.get("include_details", False)
    lines: list[str] = []
    lines.append(f"# AttackChainBuilder {__version__} - Attack Chains")
    lines.append("")
    lines.append(f"- Generated: {meta.get('generated_at', 'N/A')}")
    ctx = meta.get("context", {})
    lines.append(f"- Start phase: {ctx.get('start_phase', 'auto')}")
    lines.append(f"- Goal phase: {ctx.get('goal_phase', 'IMPACT')}")
    if ctx.get("software"):
        lines.append(f"- Target software: {', '.join(ctx['software'])}")
    lines.append(f"- CVEs analyzed: {meta.get('total_cves', 0)}")
    lines.append(f"- Chains found: {len(chains)}")
    lines.append("")

    if not chains:
        lines.append("*No attack chains found matching the given context.*")
        path.write_text("\n".join(lines), encoding="utf-8")
        return

    # Summary table
    lines.append("## Chain Summary")
    lines.append("")
    if include_details:
        lines.append("| Rank | Score | Exploitability | Viability | FP | Steps | Phases |")
        lines.append("|------|-------|---------------|-----------|----|-------|--------|")
    else:
        lines.append("| Rank | Score | Exploitability | Severity Mix | Steps | Phases |")
        lines.append("|------|-------|---------------|--------------|-------|--------|")
    for i, chain in enumerate(chains, 1):
        phases = " → ".join(PHASE_SHORT.get(s.phase, "?") for s in chain.steps)
        if include_details:
            fp_count = len(chain.fp_flags)
            lines.append(
                f"| {i} | {chain.chain_score:.1f} | {chain.exploitability:.1%} "
                f"| {chain.viability} | {fp_count} | {len(chain.steps)} | {_escape(phases)} |"
            )
        else:
            lines.append(
                f"| {i} | {chain.chain_score:.1f} | {chain.exploitability:.1%} "
                f"| {chain.severity_mix:.1%} | {len(chain.steps)} | {_escape(phases)} |"
            )
    lines.append("")

    # Detail per chain
    lines.append("## Chain Details")
    lines.append("")
    for i, chain in enumerate(chains, 1):
        lines.append(f"### Chain #{i} (Score: {chain.chain_score:.1f})")
        lines.append("")
        lines.append(f"- Exploitability: {chain.exploitability:.1%}")
        lines.append(f"- Severity mix: {chain.severity_mix:.1%}")
        lines.append(f"- Phase coverage: {chain.coverage_ratio:.0%}")
        if chain.viability != "UNKNOWN":
            lines.append(f"- **Viability: {chain.viability}**")
        if chain.fp_flags:
            lines.append(f"- **FP flags: {len(chain.fp_flags)}**")
        lines.append("")
        lines.append("| Step | CVE | Phase | Tactic | Techniques | P(exploit) | CVSS |")
        lines.append("|------|-----|-------|--------|------------|------------|------|")
        for j, s in enumerate(chain.steps, 1):
            techs = ", ".join(s.techniques[:3]) if s.techniques else "-"
            cvss_str = f"{s.cvss:.1f}" if s.cvss is not None else "N/A"
            lines.append(
                f"| {j} | {s.cve_id} | {PHASE_SHORT.get(s.phase, '?')} "
                f"| {s.tactic_id} | {techs} | {s.p_exploit:.0%} | {cvss_str} |"
            )
        lines.append("")

        # Arrow notation
        arrow = " → ".join(
            f"{s.cve_id} ({PHASE_SHORT.get(s.phase, '?')})" for s in chain.steps
        )
        lines.append(f"**Flow:** {arrow}")
        lines.append("")

        # Technical details section
        if include_details and chain.details:
            lines.append("#### Technical Details")
            lines.append("")
            for j, s in enumerate(chain.steps):
                if j < len(chain.details):
                    d = chain.details[j]
                    lines.append(f"**{s.cve_id}**:")
                    if d.exploitation_method:
                        lines.append(f"- Method: {d.exploitation_method}")
                    if d.attack_vector:
                        lines.append(f"- Vector: {d.attack_vector} | Complexity: {d.attack_complexity} | PR: {d.privileges_required}")
                    if d.prerequisites:
                        lines.append(f"- Prerequisites: {', '.join(d.prerequisites[:3])}")
                    if d.impact_summary:
                        lines.append(f"- Impact: {d.impact_summary}")
                    lines.append(f"- Maturity: {d.exploit_maturity}")
                    if d.detection_opportunities:
                        lines.append(f"- Detection: {d.detection_opportunities[0]}")
                    if d.fp_flags:
                        for fp in d.fp_flags:
                            lines.append(f"- **FP [{fp.severity}]**: {fp.flag} — {fp.detail}")
                    lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
