"""ExploitHunterAI - Local LLM-powered attack chain generation.

Uses llama-cpp-python for local inference with configurable resources.
Given an enumeration (software, versions, context), generates viable
attack chains cross-referenced with ExploitHunter CVE data.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from attackchainbuilder.models import CveRecord

DEFAULT_MODEL_REPO = "TheBloke/Phi-2-GGUF"
DEFAULT_MODEL_FILE = "phi-2.Q4_K_M.gguf"
DEFAULT_MODEL_DIR = Path.home() / ".cache" / "exploithunter_ai" / "models"
DEFAULT_CORES = 4
DEFAULT_RAM_GB = 8
DEFAULT_CONTEXT_LENGTH = 4096


@dataclass
class AIConfig:
    model_path: str | None = None
    cores: int = DEFAULT_CORES
    ram_gb: int = DEFAULT_RAM_GB
    vram_gb: float = 0.0
    context_length: int = DEFAULT_CONTEXT_LENGTH
    temperature: float = 0.3
    max_tokens: int = 2048


@dataclass
class EnumerationInput:
    software: list[dict[str, str]] = field(default_factory=list)
    context: str = ""
    goal: str = "impact"
    constraints: list[str] = field(default_factory=list)


@dataclass
class AIChainResult:
    chain: list[dict] = field(default_factory=list)
    confidence: float = 0.0
    viability: str = "UNKNOWN"
    fp_analysis: list[str] = field(default_factory=list)
    explanation: str = ""
    reasoning: str = ""


def _get_model_path(config: AIConfig) -> Path:
    if config.model_path:
        p = Path(config.model_path)
        if p.exists():
            return p
        raise FileNotFoundError(f"Model not found: {config.model_path}")

    model_dir = DEFAULT_MODEL_DIR
    model_path = model_dir / DEFAULT_MODEL_FILE
    if model_path.exists():
        return model_path

    print(f"[*] ExploitHunterAI: downloading {DEFAULT_MODEL_FILE}...")
    print(f"    Cached at: {model_dir}")
    model_dir.mkdir(parents=True, exist_ok=True)

    try:
        from huggingface_hub import hf_hub_download
        downloaded = hf_hub_download(
            repo_id=DEFAULT_MODEL_REPO,
            filename=DEFAULT_MODEL_FILE,
            local_dir=str(model_dir),
        )
        return Path(downloaded)
    except ImportError:
        raise ImportError(
            "huggingface-hub required for auto-download. "
            "Install: pip install huggingface-hub"
        )


def _load_model(config: AIConfig):
    try:
        from llama_cpp import Llama
    except ImportError:
        raise ImportError(
            "llama-cpp-python required for ExploitHunterAI. "
            "Install: pip install llama-cpp-python"
        )

    model_path = _get_model_path(config)
    n_gpu_layers = 0
    if config.vram_gb >= 3.0:
        n_gpu_layers = 32
    elif config.vram_gb >= 2.0:
        n_gpu_layers = 20
    elif config.vram_gb >= 1.0:
        n_gpu_layers = 10

    print(f"[*] ExploitHunterAI: loading {model_path.name}")
    print(f"    Threads: {config.cores} | GPU layers: {n_gpu_layers} | Ctx: {config.context_length}")

    return Llama(
        model_path=str(model_path),
        n_ctx=config.context_length,
        n_threads=config.cores,
        n_gpu_layers=n_gpu_layers,
        verbose=False,
    )


def _build_prompt(enum: EnumerationInput, cves: list[CveRecord]) -> str:
    sw_lines = []
    for sw in enum.software:
        sw_lines.append(f"- {sw.get('name', '?')} {sw.get('version', '?')}")
    sw_text = "\n".join(sw_lines) or "No specific software"

    cve_lines = []
    for cve in cves[:15]:
        phase = cve.phase.name if cve.phase else "UNKNOWN"
        poc = f", {len(cve.pocs)} PoCs" if cve.pocs else ""
        kev = ", KEV" if "cisa-kev" in cve.sources else ""
        cve_lines.append(f"- {cve.cve_id}: CVSS {cve.cvss}, {phase}, {cve.confidence}{poc}{kev}")
    cve_text = "\n".join(cve_lines) or "No CVE data"

    return f"""You are ExploitHunterAI, a cybersecurity expert in offensive security.

TASK: Build the most viable attack chain from this enumeration and vulnerabilities.

TARGET:
{sw_text}

CONTEXT: {enum.context or "Standard network engagement"}
GOAL: {enum.goal.upper()}
CONSTRAINTS: {', '.join(enum.constraints) if enum.constraints else "None"}

KNOWN VULNERABILITIES:
{cve_text}

RULES:
- Only use CVEs with real exploit evidence (PoCs, KEV, high confidence)
- Reject theoretical or unverified vulnerabilities
- Chain must progress through kill-chain phases
- Flag any potential false positives

Respond with JSON:
{{
  "chain": [
    {{"cve_id": "CVE-XXXX-XXXXX", "phase": "INITIAL_ACCESS", "rationale": "why viable", "method": "how exploited"}}
  ],
  "confidence": 85,
  "viability": "HIGH",
  "fp_flags": ["CVE-XXXX: reason"],
  "explanation": "Attack narrative",
  "reasoning": "Why this chain"
}}"""


def _parse_response(response: str) -> AIChainResult:
    text = response
    if "```" in text:
        for part in text.split("```"):
            part = part.strip()
            if part.startswith("json"):
                part = part[4:].strip()
            if part.startswith("{"):
                text = part
                break

    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return AIChainResult(explanation="Parse failed", reasoning=response[:500])

    try:
        data = json.loads(m.group())
    except json.JSONDecodeError:
        return AIChainResult(explanation="Invalid JSON", reasoning=response[:500])

    return AIChainResult(
        chain=data.get("chain", []),
        confidence=float(data.get("confidence", 0)),
        viability=data.get("viability", "UNKNOWN"),
        fp_analysis=data.get("fp_flags", []),
        explanation=data.get("explanation", ""),
        reasoning=data.get("reasoning", ""),
    )


def generate_chain(
    enumeration: EnumerationInput,
    cves: list[CveRecord],
    config: AIConfig | None = None,
) -> AIChainResult:
    """Generate an attack chain using local AI model with real-time progress."""
    import sys
    import time

    if config is None:
        config = AIConfig()

    try:
        model = _load_model(config)
    except (ImportError, FileNotFoundError) as e:
        return AIChainResult(explanation=str(e), viability="ERROR")

    prompt = _build_prompt(enumeration, cves)
    print(f"[*] ExploitHunterAI: generating chain ({len(enumeration.software)} sw, {len(cves)} CVEs)...")
    print("[*] Streaming output (real-time):")
    print("-" * 72)

    start_time = time.time()
    token_count = 0
    full_response = ""

    # Stream tokens in real-time
    stream = model.create_chat_completion(
        messages=[
            {"role": "system", "content": "You are ExploitHunterAI. Always respond with valid JSON."},
            {"role": "user", "content": prompt},
        ],
        temperature=config.temperature,
        max_tokens=config.max_tokens,
        stream=True,
    )

    for chunk in stream:
        delta = chunk["choices"][0].get("delta", {})
        content = delta.get("content", "")
        if content:
            full_response += content
            token_count += 1
            # Print token inline with flush
            sys.stdout.write(content)
            sys.stdout.flush()

            # Show progress every 20 tokens
            if token_count % 20 == 0:
                elapsed = time.time() - start_time
                tps = token_count / elapsed if elapsed > 0 else 0
                sys.stdout.write(f"\n[{token_count} tokens | {elapsed:.1f}s | {tps:.1f} tok/s] ")
                sys.stdout.flush()

    elapsed = time.time() - start_time
    tps = token_count / elapsed if elapsed > 0 else 0

    print("\n" + "-" * 72)
    print(f"[*] Generation complete: {token_count} tokens in {elapsed:.1f}s ({tps:.1f} tok/s)")

    raw = full_response
    result = _parse_response(raw)

    # Cross-reference with ExploitHunter data
    cve_map = {c.cve_id: c for c in cves}
    validated = []
    for step in result.chain:
        cve = cve_map.get(step.get("cve_id", ""))
        if cve:
            step["validated"] = True
            step["cvss"] = cve.cvss
            step["confidence"] = cve.confidence
            step["pocs"] = len(cve.pocs)
            validated.append(step)
        else:
            step["validated"] = False
            result.fp_analysis.append("{}: not in ExploitHunter data".format(
                step.get("cve_id")))

    result.chain = validated
    if validated:
        result.confidence = result.confidence * len(validated) / max(1, len(result.chain))
    else:
        result.confidence = 0.0
        result.viability = "LOW"

    return result


def parse_enumeration(
    software_str: str | None,
    context: str | None = None,
    goal: str = "impact",
    constraints: list[str] | None = None,
) -> EnumerationInput:
    """Parse CLI args into EnumerationInput."""
    software: list[dict[str, str]] = []
    if software_str:
        for item in software_str.split(","):
            item = item.strip()
            if not item:
                continue
            parts = item.split()
            if len(parts) >= 2:
                software.append({"name": parts[0], "version": " ".join(parts[1:])})
            else:
                software.append({"name": item, "version": "unknown"})

    return EnumerationInput(
        software=software,
        context=context or "",
        goal=goal,
        constraints=constraints or [],
    )
