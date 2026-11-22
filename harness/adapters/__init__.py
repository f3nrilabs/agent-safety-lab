"""Adapters: translate the neutral conversation into vendor APIs.

The vendor SDK is imported and the client is constructed only on the first completion, so
importing this package (and running the whole test suite) never needs an API key.
"""

from __future__ import annotations

from .anthropic_adapter import AnthropicAdapter
from .openai_adapter import OpenAIAdapter
from .scripted_model import (
    ScriptedCall,
    ScriptedModel,
    ScriptedStep,
    final_step,
    tool_step,
)

PROVIDERS: tuple[str, ...] = ("anthropic", "openai")


def build_adapter(
    provider: str,
    model_id: str,
    *,
    base_url: str | None = None,
    api_key: str | None = None,
) -> AnthropicAdapter | OpenAIAdapter:
    """Construct the adapter for ``provider``; credentials are resolved lazily."""
    if provider == "anthropic":
        return AnthropicAdapter(model_id, api_key=api_key)
    if provider == "openai":
        return OpenAIAdapter(model_id, api_key=api_key, base_url=base_url)
    raise ValueError(f"unknown provider: {provider!r} (expected {'|'.join(PROVIDERS)})")


__all__ = [
    "PROVIDERS",
    "AnthropicAdapter",
    "OpenAIAdapter",
    "ScriptedCall",
    "ScriptedModel",
    "ScriptedStep",
    "build_adapter",
    "final_step",
    "tool_step",
]
