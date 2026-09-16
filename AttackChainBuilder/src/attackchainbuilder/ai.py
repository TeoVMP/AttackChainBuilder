"""Optional LLM advisor for CVE classification and chain reasoning.

Uses stdlib urllib to call an OpenAI-compatible chat completions API.
Off by default; enabled via --ai flag + env vars.

Env vars:
  ACB_AI_BASE_URL  — API base URL (default: https://api.openai.com/v1)
  ACB_AI_API_KEY   — API key (required when --ai is used)
  ACB_AI_MODEL     — model name (default: gpt-4o-mini)

Graceful degradation: if anything fails, returns None and the deterministic
classifier handles it.
"""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
from typing import Any

from attackchainbuilder.models import PHASE_LABELS, KillPhase

_ENV_URL = "ACB_AI_BASE_URL"
_ENV_KEY = "ACB_AI_API_KEY"
_ENV_MODEL = "ACB_AI_MODEL"

_DEFAULT_URL = "https://api.openai.com/v1"
_DEFAULT_MODEL = "gpt-4o-mini"

_PHASE_LIST = "\n".join(f"- {p.name}: {PHASE_LABELS[p]}" for p in KillPhase)


def _get_config() -> tuple[str, str, str] | None:
    """Return (base_url, api_key, model) or None if not configured."""
    api_key = os.environ.get(_ENV_KEY, "").strip()
    if not api_key:
        return None
    base_url = os.environ.get(_ENV_URL, _DEFAULT_URL).strip().rstrip("/")
    model = os.environ.get(_ENV_MODEL, _DEFAULT_MODEL).strip()
    return base_url, api_key, model


def _chat_completion(
    base_url: str,
    api_key: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = 300,
) -> str | None:
    """Make a chat completion request. Returns response text or None on failure."""
    url = f"{base_url}/chat/completions"
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "max_tokens": max_tokens,
        "temperature": 0.2,
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )

    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"].strip()
    except (urllib.error.URLError, KeyError, IndexError, json.JSONDecodeError, OSError):
        return None


def classify_with_ai(
    description: str | None,
    cvss: float | None,
    software: list[str],
) -> tuple[str | None, str]:
    """Use LLM to classify a CVE's kill-chain phase.

    Returns (phase_name, rationale) or (None, "") on failure.
    """
    config = _get_config()
    if not config:
        return None, ""

    base_url, api_key, model = config
    system = (
        "You are a cybersecurity expert specializing in MITRE ATT&CK. "
        "Given a CVE description, classify it into ONE kill-chain phase. "
        "Respond ONLY with a JSON object: {\"phase\": \"<PHASE_NAME>\", \"rationale\": \"<brief>\"} "
        f"Valid phases:\n{_PHASE_LIST}"
    )
    user = (
        f"CVE description: {description or 'N/A'}\n"
        f"CVSS score: {cvss or 'N/A'}\n"
        f"Affected software: {', '.join(software) or 'N/A'}"
    )

    response = _chat_completion(base_url, api_key, model, system, user, max_tokens=200)
    if not response:
        return None, ""

    try:
        # Extract JSON from response (may be wrapped in markdown code block)
        text = response
        if "```" in text:
            text = text.split("```")[1]
            text = text.removeprefix("json")
            text = text.strip()
        result = json.loads(text)
        phase_name = result.get("phase", "").strip().upper().replace(" ", "_")
        rationale = result.get("rationale", "")
        # Validate phase
        try:
            KillPhase[phase_name]
            return phase_name, rationale
        except KeyError:
            return None, rationale
    except (json.JSONDecodeError, IndexError):
        return None, ""


def explain_chain(
    steps: list[dict[str, Any]],
    context_description: str,
) -> str | None:
    """Generate a narrative explanation for an attack chain.

    Returns explanation text or None on failure.
    """
    config = _get_config()
    if not config:
        return None

    base_url, api_key, model = config
    system = (
        "You are a cybersecurity threat analyst. Given a sequence of CVEs forming "
        "an attack chain, explain in 2-4 sentences why this chain is plausible and "
        "dangerous. Be concise and technical."
    )
    steps_text = "\n".join(
        f"- {s.get('cve_id', '?')} ({s.get('phase', '?')}, CVSS {s.get('cvss', 'N/A')}): "
        f"{s.get('description', 'N/A')[:120]}"
        for s in steps
    )
    user = f"Context: {context_description}\n\nAttack chain:\n{steps_text}"

    return _chat_completion(base_url, api_key, model, system, user, max_tokens=250)
