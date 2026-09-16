"""Attack chain construction: graph-based search with context-driven constraints.

Builds plausible attack chains from classified CVEs by:
1. Filtering candidates based on TargetContext (start phase, software, version)
2. Building an implicit phase-ordered graph (phase(A) < phase(B))
3. Scoring edges via software overlap + temporal proximity
4. Finding all valid chains (BFS/DFS) within length constraints
5. Deduplicating (keep the most complete/shortest chain per unique phase sequence)
"""

from __future__ import annotations

from datetime import datetime

from attackchainbuilder.models import (
    AttackChain,
    ChainStep,
    CveRecord,
    KillPhase,
    TargetContext,
)
from attackchainbuilder.normalize import tokenize_software
from attackchainbuilder.phases import tactic_for
from attackchainbuilder.scoring import compute_chain_scores, p_exploit


def build_chains(
    cves: list[CveRecord],
    context: TargetContext,
    allow_unknown: bool = False,
) -> list[AttackChain]:
    """Build and return attack chains sorted by chain_score descending."""

    # 1. Filter: only classified CVEs (unless allow_unknown)
    candidates = [
        c for c in cves
        if c.phase is not None or allow_unknown
    ]

    if not candidates:
        return []

    # 2. Apply context filters
    start_phase = context.start_phase
    goal_phase = context.goal_phase or KillPhase.IMPACT

    # If start_phase given, restrict to CVEs at or after that phase
    if start_phase is not None:
        candidates = [c for c in candidates if c.phase is not None and c.phase >= start_phase]

    # Software context filter (soft: prioritize, hard: require)
    context_tokens = set(context.software_tokens)
    if context.version_hint:
        context_tokens.update(tokenize_software(context.version_hint))

    if context_tokens and context.require_software_link:
        # Hard filter: CVE must match at least one context token
        candidates = [
            c for c in candidates
            if set(c.software_tokens) & context_tokens
        ]

    if not candidates:
        return []

    # 3. Sort candidates by phase then CVSS (highest first within each phase)
    candidates.sort(key=lambda c: (c.phase.value if c.phase is not None else 99, -(c.cvss or 0)))

    # 4. Build chains via DFS
    all_chains: list[AttackChain] = []
    _search_chains(
        candidates=candidates,
        context=context,
        context_tokens=context_tokens,
        start_phase=start_phase,
        goal_phase=goal_phase,
        current_chain=[],
        all_chains=all_chains,
        visited=set(),
    )

    # 5. Deduplicate: keep best chain per unique phase-sequence key
    best_by_key: dict[str, AttackChain] = {}
    for chain in all_chains:
        key = tuple(s.phase.value for s in chain.steps)
        existing = best_by_key.get(key)
        if existing is None or chain.chain_score > existing.chain_score:
            best_by_key[key] = chain

    # 6. Sort by score descending
    result = sorted(best_by_key.values(), key=lambda c: c.chain_score, reverse=True)
    return result


def _search_chains(
    candidates: list[CveRecord],
    context: TargetContext,
    context_tokens: set[str],
    start_phase: KillPhase | None,
    goal_phase: KillPhase,
    current_chain: list[CveRecord],
    all_chains: list[AttackChain],
    visited: set[str],
) -> None:
    """DFS search for valid attack chains."""

    # Check if current chain is complete (reached goal and meets min_steps)
    if current_chain:
        last_phase = current_chain[-1].phase
        if last_phase is not None and last_phase >= goal_phase and len(current_chain) >= context.min_steps:
            chain = _build_chain_from_records(current_chain, context, context_tokens)
            if chain.chain_score > 0:
                all_chains.append(chain)
            # Don't return — might find longer chains too (if under max_steps)

    # Stop if at max length
    if len(current_chain) >= context.max_steps:
        return

    # Determine minimum phase for next step
    if current_chain:
        last = current_chain[-1].phase
        if last is not None and last.value < KillPhase.IMPACT:
            min_phase = KillPhase(last.value + 1)  # strictly increasing
        else:
            min_phase = None  # already at max phase or unknown — no further candidates
    else:
        min_phase = start_phase

    # Find next candidates
    for cve in candidates:
        if cve.cve_id in visited:
            continue
        if cve.phase is None:
            continue
        if min_phase is not None and cve.phase < min_phase:
            continue
        # Don't go past goal (unless we already reached it)
        if (
            current_chain
            and current_chain[-1].phase is not None
            and current_chain[-1].phase >= goal_phase
        ):
            continue

        # Software context soft scoring: skip if strict mode and no overlap
        if context_tokens and context.require_software_link and not (set(cve.software_tokens) & context_tokens):
            continue

        visited.add(cve.cve_id)
        current_chain.append(cve)
        _search_chains(
            candidates, context, context_tokens,
            start_phase, goal_phase,
            current_chain, all_chains, visited,
        )
        current_chain.pop()
        visited.discard(cve.cve_id)


def _build_chain_from_records(
    records: list[CveRecord],
    context: TargetContext,
    context_tokens: set[str],
) -> AttackChain:
    """Convert a sequence of CveRecords into a scored AttackChain."""
    steps: list[ChainStep] = []
    for cve in records:
        if cve.phase is None:
            continue
        tactic_id, tactic_name = tactic_for(cve.phase)
        steps.append(
            ChainStep(
                cve_id=cve.cve_id,
                phase=cve.phase,
                tactic_id=tactic_id,
                tactic_name=tactic_name,
                techniques=cve.techniques[:],
                p_exploit=p_exploit(cve),
                cvss=cve.cvss,
                severity=cve.severity,
                software_tokens=cve.software_tokens[:],
                description=cve.description,
            )
        )

    if not steps:
        return AttackChain()

    chain = AttackChain(steps=steps)
    compute_chain_scores(chain, context, context_tokens)
    return chain


def _parse_date(date_str: str | None) -> datetime | None:
    if not date_str:
        return None
    try:
        text = date_str.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text)
    except (ValueError, TypeError):
        return None
