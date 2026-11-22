"""Anthropic Messages API adapter with tool use.

``Anthropic`` and the client are created on first use. Importing this module, constructing
the adapter and translating messages all work without credentials; only a completion
needs ``ANTHROPIC_API_KEY``.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from typing import Any

from ..protocol import (
    ChatMessage,
    MissingAPIKeyError,
    ModelTurn,
    ToolCall,
    ToolSchema,
)

DEFAULT_MAX_TOKENS = 2048
DEFAULT_TIMEOUT = 120.0

MessageParam = dict[str, Any]


def to_anthropic_messages(messages: Sequence[ChatMessage]) -> list[MessageParam]:
    """Convert neutral messages to the Messages API shape.

    Consecutive tool results are grouped into a single ``user`` message, which is what the
    API requires right after an assistant turn with ``tool_use`` blocks.
    """
    converted: list[MessageParam] = []
    tool_results: list[dict[str, Any]] = []

    def flush_tool_results() -> None:
        if tool_results:
            converted.append({"role": "user", "content": list(tool_results)})
            tool_results.clear()

    for message in messages:
        if message.role == "tool":
            block: dict[str, Any] = {"type": "tool_result", "tool_use_id": message.tool_call_id}
            block["content"] = message.text
            if message.is_error:
                block["is_error"] = True
            tool_results.append(block)
            continue
        flush_tool_results()
        if message.role == "user":
            converted.append({"role": "user", "content": [{"type": "text", "text": message.text}]})
            continue
        blocks: list[dict[str, Any]] = []
        if message.text:
            blocks.append({"type": "text", "text": message.text})
        for call in message.tool_calls:
            blocks.append(
                {
                    "type": "tool_use",
                    "id": call.id,
                    "name": call.name,
                    "input": call.arguments,
                }
            )
        if not blocks:
            blocks.append({"type": "text", "text": "(no content)"})
        converted.append({"role": "assistant", "content": blocks})
    flush_tool_results()
    return converted


def to_anthropic_tools(tools: Sequence[ToolSchema]) -> list[dict[str, Any]]:
    return [
        {"name": tool.name, "description": tool.description, "input_schema": tool.parameters}
        for tool in tools
    ]


class AnthropicAdapter:
    """Messages API with tool use."""

    provider = "anthropic"

    def __init__(
        self,
        model_id: str,
        *,
        api_key: str | None = None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        timeout: float = DEFAULT_TIMEOUT,
        client: Any | None = None,
    ) -> None:
        self.model_id = model_id
        self._api_key = api_key
        self._max_tokens = max_tokens
        self._timeout = timeout
        self._client = client

    @property
    def client(self) -> Any:
        """The SDK client, constructed on first access."""
        if self._client is None:
            api_key = self._api_key or os.environ.get("ANTHROPIC_API_KEY")
            if not api_key:
                raise MissingAPIKeyError(
                    "ANTHROPIC_API_KEY is not set. Export it or put it in .env "
                    "(see .env.example); the test suite never needs it."
                )
            from anthropic import Anthropic

            self._client = Anthropic(api_key=api_key, timeout=self._timeout)
        return self._client

    @property
    def has_client(self) -> bool:
        """Whether a client already exists (used by tests to prove laziness)."""
        return self._client is not None

    def complete(
        self,
        *,
        system: str,
        messages: Sequence[ChatMessage],
        tools: Sequence[ToolSchema],
    ) -> ModelTurn:
        response = self.client.messages.create(
            model=self.model_id,
            max_tokens=self._max_tokens,
            system=system,
            messages=to_anthropic_messages(messages),
            tools=to_anthropic_tools(tools),
        )
        texts: list[str] = []
        calls: list[ToolCall] = []
        for block in response.content:
            if block.type == "text":
                if block.text.strip():
                    texts.append(block.text.strip())
            elif block.type == "tool_use":
                calls.append(
                    ToolCall(id=block.id, name=block.name, arguments=dict(block.input or {}))
                )
        return ModelTurn(
            text="\n\n".join(texts),
            tool_calls=tuple(calls),
            stop_reason="tool_use" if calls else str(getattr(response, "stop_reason", "end_turn")),
        )
