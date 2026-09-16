"""Graph output: Mermaid (.mmd) and Graphviz DOT (.dot) for attack chain visualization."""

from __future__ import annotations

from pathlib import Path

from attackchainbuilder.models import PHASE_SHORT, AttackChain, KillPhase

# Colors by severity
SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#ca8a04",
    "LOW": "#16a34a",
    "UNKNOWN": "#6b7280",
}

PHASE_BG_COLORS = {
    KillPhase.INITIAL_ACCESS: "#dbeafe",
    KillPhase.EXECUTION: "#fef3c7",
    KillPhase.PERSISTENCE: "#fce7f3",
    KillPhase.PRIVILEGE_ESCALATION: "#ede9fe",
    KillPhase.CREDENTIAL_ACCESS: "#ffedd5",
    KillPhase.LATERAL_MOVEMENT: "#d1fae5",
    KillPhase.IMPACT: "#fee2e2",
}


def _node_id(cve_id: str) -> str:
    return cve_id.replace("-", "_").replace(".", "_")


def write_mermaid(chains: list[AttackChain], path: Path, merge: bool = False) -> None:
    """Write Mermaid flowchart(s) to .mmd file."""
    lines: list[str] = []

    if merge and len(chains) > 1:
        lines.append("flowchart LR")
        lines.append("")
        for i, chain in enumerate(chains, 1):
            lines.append(f"  subgraph chain_{i}[\"Chain #{i} — Score: {chain.chain_score:.1f}\"]")
            for j, step in enumerate(chain.steps):
                node = _node_id(step.cve_id)
                label = f"{step.cve_id}\\n{PHASE_SHORT.get(step.phase, '?')}\\nCVSS: {step.cvss or 'N/A'}"
                lines.append(f"    {node}_{i}[\"{label}\"]")
                if j > 0:
                    prev = _node_id(chain.steps[j - 1].cve_id)
                    lines.append(f"    {prev}_{i} --> {node}_{i}")
            lines.append("  end")
            lines.append("")
    else:
        for i, chain in enumerate(chains, 1):
            lines.append("---")
            lines.append(f"title: Chain #{i} — Score: {chain.chain_score:.1f}")
            lines.append("---")
            lines.append("flowchart LR")
            for j, step in enumerate(chain.steps):
                node = _node_id(step.cve_id)
                label = f"{step.cve_id}\\n{PHASE_SHORT.get(step.phase, '?')}\\nCVSS: {step.cvss or 'N/A'}"
                lines.append(f"  {node}[\"{label}\"]")
                if j > 0:
                    prev = _node_id(chain.steps[j - 1].cve_id)
                    lines.append(f"  {prev} --> {node}")
            lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


def write_dot(chains: list[AttackChain], path: Path, merge: bool = False) -> None:
    """Write Graphviz DOT digraph(s) to .dot file."""
    lines: list[str] = []

    if merge and len(chains) > 1:
        lines.append("digraph AttackChains {")
        lines.append('  rankdir=LR;')
        lines.append('  node [shape=box, style="rounded,filled", fontname="Helvetica"];')
        lines.append("")
        for i, chain in enumerate(chains, 1):
            lines.append(f'  subgraph cluster_{i} {{')
            lines.append(f'    label="Chain #{i} — Score: {chain.chain_score:.1f}";')
            lines.append('    style=dashed;')
            for j, step in enumerate(chain.steps):
                node = _node_id(step.cve_id) + f"_{i}"
                color = SEVERITY_COLORS.get(step.severity, "#6b7280")
                bg = PHASE_BG_COLORS.get(step.phase, "#f3f4f6")
                label = f"{step.cve_id}\\n{PHASE_SHORT.get(step.phase, '?')}\\nCVSS: {step.cvss or 'N/A'}"
                lines.append(f'    {node} [label="{label}", fillcolor="{bg}", color="{color}"];')
                if j > 0:
                    prev = _node_id(chain.steps[j - 1].cve_id) + f"_{i}"
                    lines.append(f"    {prev} -> {node};")
            lines.append("  }")
            lines.append("")
        lines.append("}")
    else:
        for i, chain in enumerate(chains, 1):
            lines.append(f"digraph Chain{i} {{")
            lines.append('  rankdir=LR;')
            lines.append('  node [shape=box, style="rounded,filled", fontname="Helvetica"];')
            lines.append("")
            for j, step in enumerate(chain.steps):
                node = _node_id(step.cve_id)
                color = SEVERITY_COLORS.get(step.severity, "#6b7280")
                bg = PHASE_BG_COLORS.get(step.phase, "#f3f4f6")
                label = f"{step.cve_id}\\n{PHASE_SHORT.get(step.phase, '?')}\\nCVSS: {step.cvss or 'N/A'}"
                lines.append(f'  {node} [label="{label}", fillcolor="{bg}", color="{color}"];')
                if j > 0:
                    prev = _node_id(chain.steps[j - 1].cve_id)
                    lines.append(f"  {prev} -> {node};")
            lines.append("}")
            lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
