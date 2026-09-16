"""Load ExploitHunter JSON output into CveRecord objects."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from attackchainbuilder.models import CveRecord


def load(path: Path) -> list[CveRecord]:
    """Parse an ExploitHunter JSON report into a list of CveRecord.

    Tolerant of missing fields for backward compatibility with older JSON.
    """
    text = path.read_text(encoding="utf-8")
    payload = json.loads(text)

    if not isinstance(payload, dict):
        raise TypeError(f"Expected a JSON object, got {type(payload).__name__}")

    vulns = payload.get("vulnerabilities")
    if not isinstance(vulns, list):
        raise TypeError("Missing or invalid 'vulnerabilities' array")

    records: list[CveRecord] = []
    for entry in vulns:
        if not isinstance(entry, dict):
            continue
        cve_id = (entry.get("cve_id") or "").strip()
        if not cve_id:
            continue

        # Parse PoCs — may be dicts with url/kind/origin
        raw_pocs = entry.get("pocs") or []
        pocs: list[dict[str, str]] = []
        for poc in raw_pocs:
            if isinstance(poc, dict):
                pocs.append({
                    "url": poc.get("url", ""),
                    "kind": poc.get("kind", "unknown"),
                    "origin": poc.get("origin", ""),
                })

        # Ransomware use normalization
        ransomware = entry.get("ransomware_use")
        if ransomware and isinstance(ransomware, str):
            ransomware = ransomware.strip() or None

        records.append(
            CveRecord(
                cve_id=cve_id,
                description=entry.get("description"),
                cvss=_safe_float(entry.get("cvss")),
                cvss_vector=entry.get("cvss_vector"),
                affected_software=entry.get("affected_software") or [],
                pocs=pocs,
                sources=entry.get("sources") or [],
                confidence=entry.get("confidence") or "LOW",
                published=entry.get("published"),
                kev_due_date=entry.get("kev_due_date"),
                ransomware_use=ransomware,
                cwe=entry.get("cwe") or [],
            )
        )

    return records


def _safe_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
