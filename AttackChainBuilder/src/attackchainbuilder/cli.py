"""Command line interface for AttackChainBuilder.

argparse from the standard library — zero extra dependencies.
Subcommands: build / classify / inspect.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from attackchainbuilder import __version__
from attackchainbuilder.chain import build_chains
from attackchainbuilder.classify import classify_all
from attackchainbuilder.loader import load
from attackchainbuilder.models import (
    PHASE_SHORT,
    KillPhase,
    TargetContext,
    parse_phase,
)
from attackchainbuilder.normalize import tokenize_software
from attackchainbuilder.report import write_reports

BANNER = "=" * 72


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="acb",
        description=(
            "Build plausible attack chains from ExploitHunter CVE data "
            "with MITRE ATT&CK alignment."
        ),
    )
    parser.add_argument(
        "-V", "--version", action="version", version=f"AttackChainBuilder {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # --- build subcommand ---
    build_cmd = sub.add_parser(
        "build",
        help="Build attack chains from an ExploitHunter JSON report",
    )
    build_cmd.add_argument(
        "--input",
        required=True,
        help="Path to ExploitHunter JSON report (exploited_cves_*.json)",
    )
    build_cmd.add_argument(
        "--start-phase",
        help="Phase where the attacker currently is (e.g. initial-access, lateral-movement)",
    )
    build_cmd.add_argument(
        "--goal-phase",
        default="impact",
        help="Target phase to reach (default: impact)",
    )
    build_cmd.add_argument(
        "--software",
        help="Comma-separated target software keywords (e.g. apache,wordpress)",
    )
    build_cmd.add_argument(
        "--version-hint",
        help="Version substring to match against software/description",
    )
    build_cmd.add_argument("--max-steps", type=int, default=5, help="Max chain length (default 5)")
    build_cmd.add_argument("--min-steps", type=int, default=2, help="Min chain length (default 2)")
    build_cmd.add_argument(
        "--require-software-link",
        action="store_true",
        help="Hard constraint: all steps must match target software",
    )
    build_cmd.add_argument("--top", type=int, help="Show only top N chains")
    build_cmd.add_argument("--min-score", type=float, default=0.0, help="Min chain_score filter")
    build_cmd.add_argument(
        "--allow-unknown",
        action="store_true",
        help="Include CVEs without phase classification",
    )
    build_cmd.add_argument(
        "--format",
        dest="formats",
        default="json,md,mermaid",
        help="Comma-separated formats: json,md,csv,mermaid,dot (default: json,md,mermaid)",
    )
    build_cmd.add_argument(
        "--merge-graph",
        action="store_true",
        help="Merge all chains into a single graph file",
    )
    build_cmd.add_argument("--output", default=".", help="Output directory (default: .)")
    build_cmd.add_argument(
        "--ai",
        action="store_true",
        help="Enable LLM advisor for ambiguous classifications (needs ACB_AI_* env vars)",
    )
    # New flags
    build_cmd.add_argument(
        "--search-pocs",
        action="store_true",
        help="Search GitHub for community-verified PoCs (requires network)",
    )
    build_cmd.add_argument(
        "--analyze",
        action="store_true",
        help="Analyze chain viability and detect false positives",
    )
    build_cmd.add_argument(
        "--debug",
        action="store_true",
        help="Debug mode: show classification reasoning, scoring breakdown, FP flags",
    )
    build_cmd.add_argument(
        "--details",
        action="store_true",
        help="Include full ExploitDetails in reports (attack vector, prereqs, detection)",
    )
    build_cmd.add_argument("-q", "--quiet", action="store_true", help="Minimal console output")

    # --- classify subcommand ---
    classify_cmd = sub.add_parser(
        "classify",
        help="Show per-CVE phase/technique classification (audit tool)",
    )
    classify_cmd.add_argument(
        "--input",
        required=True,
        help="Path to ExploitHunter JSON report",
    )
    classify_cmd.add_argument(
        "--format",
        dest="output_format",
        default="table",
        help="Output format: table or json (default: table)",
    )
    classify_cmd.add_argument("--output", help="Output directory (for json format)")
    classify_cmd.add_argument(
        "--allow-unknown",
        action="store_true",
        help="Show CVEs without classification",
    )
    classify_cmd.add_argument(
        "--debug",
        action="store_true",
        help="Debug mode: show classification reasoning",
    )
    classify_cmd.add_argument("-q", "--quiet", action="store_true")

    # --- inspect subcommand ---
    inspect_cmd = sub.add_parser(
        "inspect",
        help="Inspect a single CVE in detail (technical details, PoCs, sources)",
    )
    inspect_cmd.add_argument(
        "cve_id",
        help="CVE ID to inspect (e.g. CVE-2021-44228)",
    )
    inspect_cmd.add_argument(
        "--input",
        required=True,
        help="Path to ExploitHunter JSON report",
    )
    inspect_cmd.add_argument(
        "--search-pocs",
        action="store_true",
        help="Also search GitHub for community PoCs",
    )
    inspect_cmd.add_argument(
        "--format",
        dest="output_format",
        default="table",
        help="Output format: table or json (default: table)",
    )
    inspect_cmd.add_argument("--output", help="Output directory (for json format)")

    # --- ai subcommand (ExploitHunterAI) ---
    ai_cmd = sub.add_parser(
        "ai",
        help="Generate attack chains using local AI model (ExploitHunterAI)",
    )
    ai_cmd.add_argument(
        "--input",
        required=True,
        help="Path to ExploitHunter JSON report",
    )
    ai_cmd.add_argument(
        "--software",
        help="Target software with versions (e.g. 'apache 2.4.49, openssl 1.1.1k')",
    )
    ai_cmd.add_argument(
        "--enum-file",
        help="Path to enumeration file (nmap, curl, whatweb, headers, config, free text)",
    )
    ai_cmd.add_argument(
        "--context",
        help="Engagement context (e.g. 'network access, no auth, internal pentest')",
    )
    ai_cmd.add_argument(
        "--goal",
        default="impact",
        help="Target phase (default: impact)",
    )
    ai_cmd.add_argument(
        "--constraint",
        action="append",
        dest="constraints",
        help="Constraint (repeatable, e.g. --constraint 'no auth' --constraint 'network only')",
    )
    ai_cmd.add_argument(
        "--model-path",
        help="Path to GGUF model file (default: auto-download Phi-2)",
    )
    ai_cmd.add_argument(
        "--cores",
        type=int,
        default=4,
        help="CPU cores for inference (default: 4)",
    )
    ai_cmd.add_argument(
        "--ram",
        type=int,
        default=8,
        help="RAM in GB (default: 8)",
    )
    ai_cmd.add_argument(
        "--vram",
        type=float,
        default=0.0,
        help="VRAM in GB, 0=CPU only (default: 0)",
    )
    ai_cmd.add_argument(
        "--context-length",
        type=int,
        default=4096,
        help="Model context length (default: 4096)",
    )
    ai_cmd.add_argument(
        "--temperature",
        type=float,
        default=0.3,
        help="Generation temperature (default: 0.3)",
    )
    ai_cmd.add_argument(
        "--max-tokens",
        type=int,
        default=2048,
        help="Max tokens to generate (default: 2048)",
    )
    ai_cmd.add_argument(
        "--format",
        dest="output_format",
        default="table",
        help="Output: table or json (default: table)",
    )
    ai_cmd.add_argument("--output", help="Output directory (for json format)")
    ai_cmd.add_argument("-q", "--quiet", action="store_true")

    return parser


def _parse_formats(raw: str) -> list[str]:
    return [f.strip().lower() for f in raw.split(",") if f.strip()]


def cmd_build(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[!] File not found: {input_path}")
        return 1

    if not args.quiet:
        print(BANNER)
        print(f"ATTACK CHAIN BUILDER {__version__}")
        print(BANNER)

    # Load
    cves = load(input_path)
    if not args.quiet:
        print(f"[*] Loaded {len(cves)} CVEs from {input_path.name}")

    # Classify
    classify_all(cves)

    classified = sum(1 for c in cves if c.phase is not None)
    unknown = len(cves) - classified
    if not args.quiet:
        print(f"[*] Classified: {classified} | Unknown: {unknown}")

    # Debug: classification
    if args.debug:
        from attackchainbuilder.debug import debug_classify_all
        print("\n" + debug_classify_all(cves))

    # Search PoCs (optional)
    if args.search_pocs:
        from attackchainbuilder.poc_search import search_pocs
        if not args.quiet:
            print("[*] Searching GitHub for community PoCs...")
        for cve in cves:
            results = search_pocs(cve.cve_id)
            for r in results:
                if r.verified and r.url not in [p.get("url") for p in cve.pocs]:
                    cve.pocs.append({
                        "url": r.url,
                        "kind": "github-poc",
                        "origin": f"github-search ({r.stars} stars)",
                    })
        if not args.quiet:
            total_new = sum(1 for c in cves for p in cve.pocs if p.get("origin", "").startswith("github"))
            print(f"[*] Found {total_new} additional community PoCs")

    # False positive detection (pre-analysis)
    if args.debug or args.analyze:
        from attackchainbuilder.analyzer import get_cve_fp_summary
        fp_summary = get_cve_fp_summary(cves)
        if fp_summary and not args.quiet:
            print(f"\n[*] False positive flags detected in {len(fp_summary)} CVEs:")
            for cve_id, fps in fp_summary.items():
                for fp in fps:
                    print(f"    [{fp.severity}] {cve_id}: {fp.flag} — {fp.detail}")

    # Build context
    start_phase = parse_phase(args.start_phase) if args.start_phase else None
    goal_phase = parse_phase(args.goal_phase) if args.goal_phase else KillPhase.IMPACT
    software_tokens = tokenize_software(args.software) if args.software else []

    context = TargetContext(
        start_phase=start_phase,
        goal_phase=goal_phase,
        software_tokens=software_tokens,
        version_hint=args.version_hint,
        max_steps=args.max_steps,
        min_steps=args.min_steps,
        require_software_link=args.require_software_link,
    )

    if args.debug:
        from attackchainbuilder.debug import debug_context
        print("\n" + debug_context(context))

    if not args.quiet:
        ctx_parts = []
        if start_phase:
            ctx_parts.append(f"start={start_phase.name}")
        if goal_phase:
            ctx_parts.append(f"goal={goal_phase.name}")
        if software_tokens:
            ctx_parts.append(f"software={','.join(software_tokens)}")
        if args.version_hint:
            ctx_parts.append(f"version={args.version_hint}")
        print(f"[*] Context: {', '.join(ctx_parts) or 'auto'}")

    # Build chains
    chains = build_chains(cves, context, allow_unknown=args.allow_unknown)

    if not chains:
        print("[-] No attack chains found matching the given context.")
        return 0

    # Analyze chains (viability + FP)
    if args.analyze or args.debug:
        from attackchainbuilder.analyzer import analyze_all_chains
        analyze_all_chains(chains, cves)
        if not args.quiet:
            high_viab = sum(1 for c in chains if c.viability == "HIGH")
            med_viab = sum(1 for c in chains if c.viability == "MEDIUM")
            low_viab = sum(1 for c in chains if c.viability == "LOW")
            print(f"[*] Viability: HIGH={high_viab} | MEDIUM={med_viab} | LOW={low_viab}")

    # Debug: chains
    if args.debug:
        from attackchainbuilder.debug import debug_chains
        print("\n" + debug_chains(chains))

    # Filter by min-score
    if args.min_score > 0:
        chains = [c for c in chains if c.chain_score >= args.min_score]

    if args.top:
        chains = chains[: args.top]

    if not args.quiet:
        print(f"\n[*] {len(chains)} attack chains generated\n")
        _print_summary(chains, show_details=args.details or args.analyze)

    # Write reports
    formats = _parse_formats(args.formats)
    out_dir = Path(args.output)
    written = write_reports(
        chains, cves, context, formats, out_dir,
        merge_graph=args.merge_graph,
        include_details=args.details or args.analyze,
    )

    if written:
        if not args.quiet:
            print(BANNER)
            print("REPORTS WRITTEN:")
        for fmt, path in written.items():
            print(f"  [{fmt}] {path}")

    return 0


def _print_summary(chains: list, show_details: bool = False) -> None:
    print(BANNER)
    print(f"TOP {min(5, len(chains))} ATTACK CHAINS:")
    print("-" * 72)
    for i, chain in enumerate(chains[:5], 1):
        steps_str = " → ".join(
            f"{s.cve_id} ({PHASE_SHORT.get(s.phase, '?')})" for s in chain.steps
        )
        techs = " → ".join(
            ", ".join(s.techniques[:2]) if s.techniques else "-"
            for s in chain.steps
        )
        viability_str = f" | Viability: {chain.viability}" if chain.viability != "UNKNOWN" else ""
        fp_str = f" | FP flags: {len(chain.fp_flags)}" if chain.fp_flags else ""
        print(f" {i}. {steps_str}")
        print(f"    Score: {chain.chain_score:.1f} | Exploitability: {chain.exploitability:.1%} | Coverage: {chain.coverage_ratio:.0%}{viability_str}{fp_str}")
        print(f"    ATT&CK: {techs}")
        software = " → ".join(
            ", ".join(s.software_tokens[:3]) if s.software_tokens else "?"
            for s in chain.steps
        )
        print(f"    Software: {software}")

        if show_details and chain.details:
            for j, step in enumerate(chain.steps):
                if j < len(chain.details):
                    d = chain.details[j]
                    print(f"    [{j+1}] {step.cve_id}: {d.exploitation_method or 'N/A'} | maturity={d.exploit_maturity}")
                    if d.prerequisites:
                        print(f"        prereqs: {', '.join(d.prerequisites[:3])}")
                    if d.impact_summary:
                        print(f"        impact: {d.impact_summary}")
                    if d.fp_flags:
                        for fp in d.fp_flags:
                            print(f"        FP: [{fp.severity}] {fp.flag}")

        print()


def cmd_classify(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[!] File not found: {input_path}")
        return 1

    cves = load(input_path)
    classify_all(cves)

    if not args.allow_unknown:
        cves = [c for c in cves if c.phase is not None]

    # Debug mode
    if args.debug:
        from attackchainbuilder.debug import debug_classify_all
        print(debug_classify_all(cves))
        return 0

    if args.output_format == "json":
        import json
        data = []
        for c in cves:
            data.append({
                "cve_id": c.cve_id,
                "phase": c.phase.name if c.phase is not None else None,
                "phase_confidence": c.phase_confidence,
                "techniques": c.techniques,
                "cvss": c.cvss,
                "cvss_vector": c.cvss_vector,
                "cwe": c.cwe,
            })
        if args.output:
            out_path = Path(args.output) / "classification.json"
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            print(f"[*] Written to {out_path}")
        else:
            print(json.dumps(data, indent=2))
    else:
        # Table format
        print(f"{'CVE ID':<20} {'Phase':<25} {'Conf':<8} {'Techniques':<30} {'CVSS':<6} {'Vector'}")
        print("-" * 110)
        for c in cves:
            phase_str = c.phase.name if c.phase is not None else "UNKNOWN"
            techs = ", ".join(c.techniques[:3]) if c.techniques else "-"
            cvss_str = f"{c.cvss:.1f}" if c.cvss is not None else "N/A"
            vector_short = (c.cvss_vector or "-")[:40]
            print(f"{c.cve_id:<20} {phase_str:<25} {c.phase_confidence:<8} {techs:<30} {cvss_str:<6} {vector_short}")

    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    """Inspect a single CVE in full technical detail."""
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[!] File not found: {input_path}")
        return 1

    cve_id = args.cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        print(f"[!] Invalid CVE ID: {args.cve_id} (expected CVE-XXXX-NNNNN)")
        return 2

    cves = load(input_path)
    classify_all(cves)

    target = None
    for c in cves:
        if c.cve_id == cve_id:
            target = c
            break

    if target is None:
        print(f"[!] CVE {cve_id} not found in {input_path.name}")
        return 1

    from attackchainbuilder.analyzer import assess_viability, detect_false_positives
    from attackchainbuilder.details import extract_details
    from attackchainbuilder.scoring import p_exploit

    details = extract_details(target)
    fps = detect_false_positives(target)
    details.fp_flags = fps
    viability = assess_viability(target, details)
    p = p_exploit(target)

    if args.output_format == "json":
        import json
        data = {
            "cve_id": target.cve_id,
            "cvss": target.cvss,
            "cvss_vector": target.cvss_vector,
            "cwe": target.cwe,
            "confidence": target.confidence,
            "sources": target.sources,
            "pocs": target.pocs,
            "ransomware_use": target.ransomware_use,
            "kev_due_date": target.kev_due_date,
            "phase": target.phase.name if target.phase is not None else None,
            "phase_confidence": target.phase_confidence,
            "techniques": target.techniques,
            "p_exploit": round(p, 4),
            "viability": viability,
            "exploit_details": {
                "attack_vector": details.attack_vector,
                "attack_complexity": details.attack_complexity,
                "privileges_required": details.privileges_required,
                "user_interaction": details.user_interaction,
                "scope": details.scope,
                "impact_confidentiality": details.impact_confidentiality,
                "impact_integrity": details.impact_integrity,
                "impact_availability": details.impact_availability,
                "exploitation_method": details.exploitation_method,
                "prerequisites": details.prerequisites,
                "impact_summary": details.impact_summary,
                "detection_opportunities": details.detection_opportunities,
                "exploit_maturity": details.exploit_maturity,
            },
            "false_positive_flags": [
                {"flag": f.flag, "severity": f.severity, "detail": f.detail}
                for f in fps
            ],
        }

        # Community PoCs
        if args.search_pocs:
            from attackchainbuilder.poc_search import search_pocs
            community_pocs = search_pocs(cve_id)
            data["community_pocs"] = [
                {"url": r.url, "stars": r.stars, "forks": r.forks, "verified": r.verified}
                for r in community_pocs
            ]

        if args.output:
            out_path = Path(args.output) / f"{cve_id}.json"
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            print(f"[*] Written to {out_path}")
        else:
            print(json.dumps(data, indent=2))
    else:
        # Table format
        print(BANNER)
        print(f"INSPECT: {target.cve_id}")
        print(BANNER)
        print(f"Description     : {target.description or 'N/A'}")
        print(f"CVSS            : {target.cvss} ({target.severity})")
        print(f"CVSS Vector     : {target.cvss_vector or 'N/A'}")
        print(f"CWE             : {', '.join(target.cwe) or 'N/A'}")
        print(f"Confidence      : {target.confidence}")
        print(f"Published       : {target.published or 'N/A'}")
        print(f"KEV Due Date    : {target.kev_due_date or 'N/A'}")
        print(f"Ransomware Use  : {target.ransomware_use or 'N/A'}")
        print()
        print(f"Phase           : {target.phase.name if target.phase is not None else 'UNKNOWN'} ({target.phase_confidence})")
        print(f"Techniques      : {', '.join(target.techniques) or 'N/A'}")
        print(f"p(exploit)      : {p:.4f}")
        print(f"Viability       : {viability}")
        print()

        print("EXPLOIT DETAILS:")
        print(f"  Attack Vector       : {details.attack_vector or 'N/A'}")
        print(f"  Attack Complexity   : {details.attack_complexity or 'N/A'}")
        print(f"  Privileges Required : {details.privileges_required or 'N/A'}")
        print(f"  User Interaction    : {details.user_interaction or 'N/A'}")
        print(f"  Scope               : {details.scope or 'N/A'}")
        print(f"  CIA Impact          : C={details.impact_confidentiality} I={details.impact_integrity} A={details.impact_availability}")
        print(f"  Method              : {details.exploitation_method or 'N/A'}")
        print(f"  Prerequisites       : {', '.join(details.prerequisites) or 'N/A'}")
        print(f"  Impact              : {details.impact_summary or 'N/A'}")
        print(f"  Exploit Maturity    : {details.exploit_maturity}")
        print()

        print("SOURCES:")
        for src in details.sources:
            print(f"  [{src['credibility']}] {src['name']}")
        print()

        print("PoCs / EXPLOITS:")
        for poc in details.pocs:
            print(f"  [{poc['kind']}] {poc['url']} (via {poc['origin']})")
        print()

        if details.detection_opportunities:
            print("DETECTION OPPORTUNITIES:")
            for det in details.detection_opportunities:
                print(f"  - {det}")
            print()

        if fps:
            print("FALSE POSITIVE FLAGS:")
            for fp in fps:
                print(f"  [{fp.severity}] {fp.flag}: {fp.detail}")
            print()

        # Community PoCs
        if args.search_pocs:
            from attackchainbuilder.poc_search import search_pocs
            print("COMMUNITY PoCs (GitHub):")
            community = search_pocs(cve_id)
            if community:
                for r in community:
                    verified = "VERIFIED" if r.verified else "unverified"
                    print(f"  [{verified}] {r.url} ({r.stars} stars, {r.forks} forks)")
            else:
                print("  No community PoCs found.")
            print()

    return 0


def cmd_ai(args: argparse.Namespace) -> int:
    """Generate attack chains using ExploitHunterAI local model."""
    from attackchainbuilder.ai_local import (
        AIConfig,
        generate_chain,
        parse_enumeration,
    )

    input_path = Path(args.input)
    if not input_path.exists():
        print("[!] File not found: " + str(input_path))
        return 1

    # Require either --software, --enum-file, or --context
    if not args.software and not args.context and not args.enum_file:
        print("[!] Provide --software, --enum-file, or --context for AI analysis")
        return 1

    if not args.quiet:
        print(BANNER)
        print("ExploitHunterAI - Local LLM Attack Chain Generation")
        print(BANNER)

    # Load and classify CVEs
    cves = load(input_path)
    classify_all(cves)
    if not args.quiet:
        classified = sum(1 for c in cves if c.phase is not None)
        print(f"[*] Loaded {len(cves)} CVEs ({classified} classified)")

    # Build enumeration input
    enumeration = parse_enumeration(
        software_str=args.software,
        context=args.context,
        goal=args.goal,
        constraints=args.constraints,
        enum_file=args.enum_file,
    )

    if not args.quiet:
        sw_list = [s["name"] + " " + s["version"] for s in enumeration.software]
        print("[*] Target software: " + str(sw_list))
        print("[*] Context: " + (enumeration.context or "N/A"))
        print("[*] Goal: " + enumeration.goal)
        if enumeration.attack_phase:
            print("[*] Attack phase: " + enumeration.attack_phase)
        print(f"[*] Resources: {args.cores} cores, {args.ram}GB RAM, {args.vram}GB VRAM")

    # Configure AI
    config = AIConfig(
        model_path=args.model_path,
        cores=args.cores,
        ram_gb=args.ram,
        vram_gb=args.vram,
        context_length=args.context_length,
        temperature=args.temperature,
        max_tokens=args.max_tokens,
    )

    # Generate chain
    result = generate_chain(enumeration, cves, config)

    if result.viability == "ERROR":
        print("[!] " + result.explanation)
        return 1

    # Display results
    if not args.quiet:
        print("\n[*] AI Analysis Complete")
        print("    Viability: " + result.viability)
        print(f"    Confidence: {result.confidence:.1f}%")
        print("    Chain length: " + str(len(result.chain)))
        if result.fp_analysis:
            print("    FP flags: " + str(len(result.fp_analysis)))
        print()

    if args.output_format == "json":
        import json
        data = {
            "tool": "ExploitHunterAI",
            "enumeration": {
                "software": enumeration.software,
                "context": enumeration.context,
                "goal": enumeration.goal,
                "constraints": enumeration.constraints,
            },
            "result": {
                "chain": result.chain,
                "confidence": result.confidence,
                "viability": result.viability,
                "fp_analysis": result.fp_analysis,
                "explanation": result.explanation,
                "reasoning": result.reasoning,
            },
            "resources": {"cores": args.cores, "ram_gb": args.ram, "vram_gb": args.vram},
        }
        if args.output:
            out_path = Path(args.output) / "ai_chain.json"
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            print("[*] Written to " + str(out_path))
        else:
            print(json.dumps(data, indent=2))
    else:
        # Table format
        print(BANNER)
        print("ExploitHunterAI - ATTACK CHAIN RESULT")
        print(BANNER)

        if result.chain:
            print(f"\nRECOMMENDED CHAIN (Confidence: {result.confidence:.1f}%):")
            print("-" * 72)
            for i, step in enumerate(result.chain, 1):
                cve_id = step.get("cve_id", "?")
                phase = step.get("phase", "?")
                method = step.get("method", "N/A")
                rationale = step.get("rationale", "N/A")
                cvss = step.get("cvss", "N/A")
                pocs = step.get("pocs", 0)
                validated = "VALIDATED" if step.get("validated") else "UNVERIFIED"

                print(f"  {i}. {cve_id} ({phase})")
                print(f"     CVSS: {cvss} | PoCs: {pocs} | Status: {validated}")
                print("     Method: " + str(method))
                print("     Rationale: " + str(rationale))
                print()

            # Arrow notation
            parts = []
            for s in result.chain:
                parts.append(s.get("cve_id", "?") + " (" + s.get("phase", "?") + ")")
            arrow = " -> ".join(parts)
            print("FLOW: " + arrow)
        else:
            print("\n[-] No viable attack chain found for this enumeration.")

        if result.explanation:
            print("\nEXPLANATION:\n" + result.explanation)

        if result.fp_analysis:
            print("\nFALSE POSITIVE ANALYSIS:")
            for fp in result.fp_analysis:
                print("  [!] " + fp)

        if result.reasoning:
            print("\nREASONING:\n" + result.reasoning)

    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "build":
        return cmd_build(args)
    if args.command == "classify":
        return cmd_classify(args)
    if args.command == "inspect":
        return cmd_inspect(args)
    if args.command == "ai":
        return cmd_ai(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
