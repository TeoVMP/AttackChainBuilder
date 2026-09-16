"""Tests for attack chain construction."""

from __future__ import annotations

from attackchainbuilder.chain import build_chains
from attackchainbuilder.classify import classify_all
from attackchainbuilder.loader import load
from attackchainbuilder.models import KillPhase, TargetContext


def test_build_chains_basic(sample_json_path):
    cves = load(sample_json_path)
    classify_all(cves)
    context = TargetContext(start_phase=KillPhase.INITIAL_ACCESS, goal_phase=KillPhase.IMPACT)
    chains = build_chains(cves, context)
    assert len(chains) > 0
    for chain in chains:
        assert chain.steps[0].phase >= KillPhase.INITIAL_ACCESS
        assert chain.steps[-1].phase == KillPhase.IMPACT
        assert chain.chain_score > 0


def test_build_chains_strictly_increasing(sample_json_path):
    cves = load(sample_json_path)
    classify_all(cves)
    context = TargetContext()
    chains = build_chains(cves, context)
    for chain in chains:
        phases = [s.phase for s in chain.steps]
        for i in range(1, len(phases)):
            assert phases[i] > phases[i - 1], f"Phases not strictly increasing: {phases}"


def test_build_chains_min_steps(sample_json_path):
    cves = load(sample_json_path)
    classify_all(cves)
    context = TargetContext(min_steps=3)
    chains = build_chains(cves, context)
    for chain in chains:
        assert len(chain.steps) >= 3


def test_build_chains_max_steps(sample_json_path):
    cves = load(sample_json_path)
    classify_all(cves)
    context = TargetContext(max_steps=2)
    chains = build_chains(cves, context)
    for chain in chains:
        assert len(chain.steps) <= 2


def test_build_chains_start_phase(sample_json_path):
    cves = load(sample_json_path)
    classify_all(cves)
    context = TargetContext(start_phase=KillPhase.LATERAL_MOVEMENT)
    chains = build_chains(cves, context)
    for chain in chains:
        assert chain.steps[0].phase >= KillPhase.LATERAL_MOVEMENT


def test_build_chains_empty_input():
    context = TargetContext()
    chains = build_chains([], context)
    assert chains == []


def test_build_chains_no_matching(sample_json_path):
    cves = load(sample_json_path)
    classify_all(cves)
    # Require IMPACT start — probably no CVE has IMPACT as start
    context = TargetContext(start_phase=KillPhase.IMPACT, goal_phase=KillPhase.IMPACT)
    chains = build_chains(cves, context)
    # May or may not find chains depending on data, but should not crash
    assert isinstance(chains, list)


def test_build_chains_sorted_by_score(sample_json_path):
    cves = load(sample_json_path)
    classify_all(cves)
    context = TargetContext()
    chains = build_chains(cves, context)
    scores = [c.chain_score for c in chains]
    assert scores == sorted(scores, reverse=True)


def test_build_chains_deduplication(sample_json_path):
    """Two chains with the same phase sequence should be deduplicated."""
    cves = load(sample_json_path)
    classify_all(cves)
    context = TargetContext()
    chains = build_chains(cves, context)
    phase_keys = [tuple(s.phase.value for s in c.steps) for c in chains]
    # No duplicate phase sequences
    assert len(phase_keys) == len(set(phase_keys))
