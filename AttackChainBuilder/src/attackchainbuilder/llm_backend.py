"""Unified LLM backend interface.

Supports multiple backends:
- local: llama-cpp-python (local inference)
- opencode: OpenCode's configured agent
- openai: OpenAI-compatible API (OpenAI, Azure, etc.)
- custom: Any OpenAI-compatible endpoint

Configuration priority: CLI flags > env vars > opencode.json > defaults
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class LLMConfig:
    """Configuration for LLM backend."""

    backend: str = "local"  # local | opencode | openai | custom
    api_url: str = ""
    api_key: str = ""
    model: str = ""
    temperature: float = 0.3
    max_tokens: int = 1024
    # Local backend specific
    model_path: str | None = None
    cores: int = 4
    ram_gb: int = 8
    vram_gb: float = 0.0
    context_length: int = 2048


@dataclass
class LLMResponse:
    """Response from LLM backend."""

    content: str = ""
    tokens_used: int = 0
    elapsed: float = 0.0
    backend: str = ""
    model: str = ""
    error: str = ""


# OpenCode config paths
_OPENCODE_CONFIG_PATHS = [
    Path.home() / ".config" / "opencode" / "opencode.json",
    Path.home() / ".config" / "opencode" / "opencode.jsonc",
    Path("opencode.json"),
    Path("opencode.jsonc"),
]

# Default API endpoints
_DEFAULT_ENDPOINTS = {
    "openai": "https://api.openai.com/v1",
    "opencode": "https://api.opencode.ai/v1",
}


def _load_opencode_config() -> dict[str, Any]:
    """Try to load OpenCode configuration."""
    for path in _OPENCODE_CONFIG_PATHS:
        if path.exists():
            try:
                text = path.read_text(encoding="utf-8")
                # Remove JSONC comments
                import re
                text = re.sub(r"//.*$", "", text, flags=re.MULTILINE)
                text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
                return json.loads(text)
            except (json.JSONDecodeError, OSError):
                continue
    return {}


def _resolve_config(backend: str | None = None,
                    api_url: str | None = None,
                    api_key: str | None = None,
                    model: str | None = None) -> LLMConfig:
    """Resolve LLM configuration from CLI, env, opencode config, defaults."""

    # 1. Start with defaults
    config = LLMConfig()

    # 2. Load OpenCode config if exists
    oc_config = _load_opencode_config()
    if oc_config:
        # Check for provider/model configuration
        providers = oc_config.get("providers", {})
        if providers:
            # Use first configured provider
            for prov in providers.values():
                if prov.get("api_url"):
                    config.api_url = prov["api_url"]
                if prov.get("api_key"):
                    config.api_key = prov["api_key"]
                if prov.get("model"):
                    config.model = prov["model"]
                break

        # Check for agent configuration
        agents = oc_config.get("agents", {})
        if agents:
            for agent in agents.values():
                if agent.get("model"):
                    config.model = agent["model"]
                break

    # 3. Override with environment variables
    config.api_key = os.environ.get("OPENAI_API_KEY",
                     os.environ.get("ACB_AI_API_KEY",
                     os.environ.get("LLM_API_KEY", config.api_key)))
    config.api_url = os.environ.get("OPENAI_API_BASE",
                    os.environ.get("ACB_AI_BASE_URL",
                    os.environ.get("LLM_API_URL", config.api_url)))
    config.model = os.environ.get("OPENAI_MODEL",
                   os.environ.get("ACB_AI_MODEL",
                   os.environ.get("LLM_MODEL", config.model)))

    # 4. Override with CLI flags (highest priority)
    if backend:
        config.backend = backend
    if api_url:
        config.api_url = api_url
    if api_key:
        config.api_key = api_key
    if model:
        config.model = model

    # 5. Set defaults based on backend
    if config.backend == "openai" and not config.api_url:
        config.api_url = _DEFAULT_ENDPOINTS["openai"]
    elif config.backend == "opencode" and not config.api_url:
        config.api_url = _DEFAULT_ENDPOINTS["opencode"]

    if config.backend in ("openai", "opencode", "custom") and not config.model:
        config.model = "gpt-4o-mini"

    return config


class LLMBackend:
    """Unified LLM backend interface."""

    def __init__(self, config: LLMConfig):
        self.config = config
        self._local_model = None

    def generate(self, prompt: str, stream: bool = True) -> LLMResponse:
        """Generate text from prompt using configured backend."""
        if self.config.backend == "local":
            return self._generate_local(prompt, stream)
        elif self.config.backend in ("openai", "opencode", "custom"):
            return self._generate_remote(prompt, stream)
        else:
            return LLMResponse(error="Unknown backend: " + self.config.backend)

    def _generate_local(self, prompt: str, stream: bool) -> LLMResponse:
        """Generate using local llama-cpp-python model."""
        try:
            from attackchainbuilder.ai_local import AIConfig, _load_model
        except ImportError:
            return LLMResponse(error="llama-cpp-python not installed")

        if self._local_model is None:
            ai_config = AIConfig(
                model_path=self.config.model_path,
                cores=self.config.cores,
                ram_gb=self.config.ram_gb,
                vram_gb=self.config.vram_gb,
                context_length=self.config.context_length,
            )
            try:
                self._local_model = _load_model(ai_config)
            except (ImportError, FileNotFoundError) as e:
                return LLMResponse(error=str(e))

        start = time.time()
        token_count = 0
        full_response = ""

        if stream:
            result = self._local_model(
                prompt,
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
                stream=True,
            )
            for chunk in result:
                content = chunk.get("choices", [{}])[0].get("text", "")
                if content:
                    full_response += content
                    token_count += 1
                    sys.stdout.write(content)
                    sys.stdout.flush()
                    if token_count % 20 == 0:
                        elapsed = time.time() - start
                        tps = token_count / elapsed if elapsed > 0 else 0
                        sys.stdout.write(f"\n[{token_count} tokens | {elapsed:.1f}s | {tps:.1f} tok/s] ")
                        sys.stdout.flush()
        else:
            result = self._local_model(
                prompt,
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
                stream=False,
            )
            full_response = result.get("choices", [{}])[0].get("text", "")
            token_count = result.get("usage", {}).get("total_tokens", 0)

        elapsed = time.time() - start
        return LLMResponse(
            content=full_response,
            tokens_used=token_count,
            elapsed=elapsed,
            backend="local",
            model=self.config.model_path or "phi-2",
        )

    def _generate_remote(self, prompt: str, stream: bool) -> LLMResponse:
        """Generate using remote OpenAI-compatible API."""
        if not self.config.api_url:
            return LLMResponse(error="No API URL configured")

        url = self.config.api_url.rstrip("/") + "/chat/completions"

        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + (self.config.api_key or "dummy"),
        }

        payload = {
            "model": self.config.model or "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": "You are ExploitHunterAI, a cybersecurity expert. Always respond with valid JSON."},
                {"role": "user", "content": prompt},
            ],
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "stream": stream,
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")

        ctx = ssl.create_default_context()
        start = time.time()
        token_count = 0
        full_response = ""

        try:
            if stream:
                with urllib.request.urlopen(req, timeout=120, context=ctx) as resp:
                    for line in resp:
                        line = line.decode("utf-8").strip()
                        if not line or line == "data: [DONE]":
                            continue
                        if line.startswith("data: "):
                            try:
                                chunk = json.loads(line[6:])
                                delta = chunk.get("choices", [{}])[0].get("delta", {})
                                content = delta.get("content", "")
                                if content:
                                    full_response += content
                                    token_count += 1
                                    sys.stdout.write(content)
                                    sys.stdout.flush()
                                    if token_count % 20 == 0:
                                        elapsed = time.time() - start
                                        tps = token_count / elapsed if elapsed > 0 else 0
                                        sys.stdout.write(f"\n[{token_count} tokens | {elapsed:.1f}s | {tps:.1f} tok/s] ")
                                        sys.stdout.flush()
                            except json.JSONDecodeError:
                                continue
            else:
                with urllib.request.urlopen(req, timeout=120, context=ctx) as resp:
                    result = json.loads(resp.read().decode("utf-8"))
                    full_response = result.get("choices", [{}])[0].get("message", {}).get("content", "")
                    token_count = result.get("usage", {}).get("total_tokens", 0)

        except urllib.error.HTTPError as e:
            error_body = ""
            try:
                error_body = e.read().decode("utf-8")[:200]
            except OSError:
                pass
            return LLMResponse(error=f"HTTP {e.code}: {error_body}")
        except urllib.error.URLError as e:
            return LLMResponse(error="Connection error: " + str(e.reason))
        except OSError as e:
            return LLMResponse(error="Error: " + str(e))

        elapsed = time.time() - start
        return LLMResponse(
            content=full_response,
            tokens_used=token_count,
            elapsed=elapsed,
            backend=self.config.backend,
            model=self.config.model,
        )


def create_backend(backend: str | None = None,
                   api_url: str | None = None,
                   api_key: str | None = None,
                   model: str | None = None,
                   **kwargs) -> LLMBackend:
    """Create an LLM backend with resolved configuration."""
    config = _resolve_config(backend, api_url, api_key, model)
    # Apply additional kwargs
    for k, v in kwargs.items():
        if hasattr(config, k) and v is not None:
            setattr(config, k, v)
    return LLMBackend(config)


def list_backends() -> dict[str, str]:
    """List available backends and their status."""
    backends = {
        "local": "Local inference (llama-cpp-python)",
        "openai": "OpenAI API (GPT-4, GPT-3.5, etc.)",
        "opencode": "OpenCode's configured agent",
        "custom": "Custom OpenAI-compatible endpoint",
    }

    # Check availability
    status = {}
    for name, desc in backends.items():
        if name == "local":
            import importlib.util
            if importlib.util.find_spec("llama_cpp"):
                status[name] = desc + " [available]"
            else:
                status[name] = desc + " [not installed]"
        elif name in ("openai", "opencode", "custom"):
            config = _resolve_config(backend=name)
            if config.api_key:
                status[name] = desc + " [configured]"
            else:
                status[name] = desc + " [no API key]"
        else:
            status[name] = desc

    return status
