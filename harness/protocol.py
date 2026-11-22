"""Provider-neutral conversation types shared by the agent loop and the adapters.

The agent loop never imports a vendor SDK. It speaks this small vocabulary, and every
adapter translates it into (and out of) the shape its API expects. That keeps the loop
testable against the scripted model and keeps API-key handling inside the adapters.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Literal, Protocol

Role = Literal["user", "assistant", "tool"]


class AdapterError(RuntimeError):
    """Base class for adapter failures that should be reported to the user verbatim."""


class MissingAPIKeyError(AdapterError):
    """Raised when an adapter needs a credential that the environment does not provide."""


@dataclass(frozen=True)
class ToolSchema:
    """A tool as advertised to the model."""

    name: str
    description: str
    parameters: dict[str, Any]


@dataclass(frozen=True)
class ToolCall:
    """One tool invocation requested by the model."""

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class ChatMessage:
    """One turn of a provider-neutral conversation."""

    role: Role
    text: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    tool_call_id: str = ""
    tool_name: str = ""
    is_error: bool = False


@dataclass(frozen=True)
class ModelTurn:
    """What one model completion produced."""

    text: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    stop_reason: str = "end_turn"


class ModelAdapter(Protocol):
    """The interface every adapter (real or scripted) implements."""

    provider: str
    model_id: str

    def complete(
        self,
        *,
        system: str,
        messages: list[ChatMessage] | tuple[ChatMessage, ...],
        tools: list[ToolSchema] | tuple[ToolSchema, ...],
    ) -> ModelTurn:
        """Return the model's next turn for the given conversation."""
        ...


def parse_arguments(raw: str) -> dict[str, Any]:
    """Parse a JSON argument string, tolerating models that emit malformed JSON.

    A malformed payload is passed through under ``_unparsed_arguments`` so the mock tool
    can reject it visibly instead of the harness crashing mid-run.
    """
    text = (raw or "").strip()
    if not text:
        return {}
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return {"_unparsed_arguments": raw}
    if isinstance(value, dict):
        return value
    return {"_value": value}
