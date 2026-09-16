"""Report writers: JSON + Markdown + CSV + graph (Mermaid/DOT)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from attackchainbuilder.models import AttackChain, CveRecord, TargetContext
from attackchainbuilder.report import csv_out, graph, json_out, markdown

WRITERS = {
    "json": json_out,
    "md": markdown,
    "markdown": markdown,
    "csv": csv_out,
    "mermaid": graph,
    "dot": graph,
}

EXTENSIONS = {
    "json": ".json",
    "md": ".md",
    "markdown": ".md",
    "csv": ".csv",
    "mermaid": ".mmd",
    "dot": ".dot",
}


def write_reports(
    chains: list[AttackChain],
    cves: list[CveRecord],
    context: TargetContext,
    formats: list[str],
    output_dir: Path,
    merge_graph: bool = False,
    include_details: bool = False,
) -> dict[str, Path]:
    """Write every requested format. Returns {format: written_path}."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
    stem = f"attack_chains_{stamp}"
    output_dir.mkdir(parents=True, exist_ok=True)

    meta = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total_cves": len(cves),
        "chains_found": len(chains),
        "include_details": include_details,
        "context": {
            "start_phase": context.start_phase.name if context.start_phase else "auto",
            "goal_phase": context.goal_phase.name if context.goal_phase else "IMPACT",
            "software": context.software_tokens,
            "version": context.version_hint,
            "max_steps": context.max_steps,
            "min_steps": context.min_steps,
        },
    }

    written: dict[str, Path] = {}
    mermaid_written = False
    dot_written = False

    for fmt in formats:
        if fmt in ("mermaid", "dot"):
            if fmt == "mermaid" and not mermaid_written:
                path = output_dir / f"{stem}.mmd"
                graph.write_mermaid(chains, path, merge=merge_graph)
                written["mermaid"] = path
                mermaid_written = True
            elif fmt == "dot" and not dot_written:
                path = output_dir / f"{stem}.dot"
                graph.write_dot(chains, path, merge=merge_graph)
                written["dot"] = path
                dot_written = True
            continue

        module = WRITERS.get(fmt)
        if module is None:
            print(f"[!] Unknown format '{fmt}' (choose from: json, md, csv, mermaid, dot)")
            continue
        path = output_dir / f"{stem}{EXTENSIONS[fmt]}"
        module.write(chains, path, meta)
        written[fmt] = path

    return written
