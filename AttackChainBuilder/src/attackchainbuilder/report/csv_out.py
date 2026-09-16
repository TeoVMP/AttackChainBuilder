"""CSV report writer for attack chains.

Security: every cell is sanitized against CSV/Formula injection.
"""

from __future__ import annotations

import csv
from pathlib import Path

from attackchainbuilder.models import PHASE_SHORT, AttackChain

_FORMULA_PREFIXES = ("=", "+", "-", "@")

HEADER = [
    "Rank",
    "Chain Score",
    "Exploitability",
    "Severity Mix",
    "Coverage Ratio",
    "Viability",
    "FP Flags",
    "Steps",
    "Phases",
    "Techniques",
    "CVE IDs",
    "CVSS Scores",
    "Software",
    "Exploit Methods",
    "Maturity",
]


def safe_cell(value: object) -> str:
    text = "" if value is None else str(value)
    if text and text[0] in _FORMULA_PREFIXES:
        return "'" + text
    return text


def write(chains: list[AttackChain], path: Path, meta: dict) -> None:
    del meta
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(HEADER)
        for i, chain in enumerate(chains, 1):
            phases = " → ".join(PHASE_SHORT.get(s.phase, "?") for s in chain.steps)
            techs = "; ".join(
                t for s in chain.steps for t in s.techniques[:2]
            ) or "-"
            cves = "; ".join(s.cve_id for s in chain.steps)
            scores = "; ".join(
                f"{s.cvss:.1f}" if s.cvss is not None else "N/A" for s in chain.steps
            )
            software = "; ".join(
                ", ".join(s.software_tokens[:3]) for s in chain.steps if s.software_tokens
            )
            # New columns
            fp_count = len(chain.fp_flags)
            methods = "; ".join(
                d.exploitation_method or "-" for d in chain.details if d
            ) if chain.details else "-"
            maturities = "; ".join(
                d.exploit_maturity for d in chain.details if d
            ) if chain.details else "-"
            writer.writerow(
                [
                    str(i),
                    f"{chain.chain_score:.1f}",
                    f"{chain.exploitability:.4f}",
                    f"{chain.severity_mix:.4f}",
                    f"{chain.coverage_ratio:.4f}",
                    chain.viability,
                    str(fp_count),
                    str(len(chain.steps)),
                    safe_cell(phases),
                    safe_cell(techs),
                    safe_cell(cves),
                    scores,
                    safe_cell(software),
                    safe_cell(methods),
                    safe_cell(maturities),
                ]
            )
