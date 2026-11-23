"""OpenAI-compatible Chat Completions adapter with tools.

Works against OpenAI itself and against any OpenAI-compatible endpoint (DeepSeek, GLM,
local gateways) through ``--base-url``. The client is constructed on first use, so importing
this module and running the tests never needs ``OPENAI_API_KEY``.
"""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Sequence
from typing import Any

from ..protocol import (
    ChatMessage,
    MissingAPIKeyError,
    ModelTurn,
    ToolCall,
    ToolSchema,
    parse_arguments,
)

DEFAULT_MAX_TOKENS = 2048
DEFAULT_TIMEOUT = 120.0

MessageParam = dict[str, Any]


def to_openai_messages(messages: Sequence[ChatMessage], system: str) -> list[MessageParam]:
    """Convert neutral messages to Chat Completions messages."""
    converted: list[MessageParam] = [{"role": "system", "content": system}]
    for message in messages:
        if message.role == "user":
            converted.append({"role": "user", "content": message.text})
        elif message.role == "tool":
            converted.append(
                {
                    "role": "tool",
                    "tool_call_id": message.tool_call_id,
                    "content": message.text,
                }
            )
        else:
            entry: MessageParam = {"role": "assistant", "content": message.text or None}
            if message.tool_calls:
                entry["tool_calls"] = [
                    {
                        "id": call.id,
                        "type": "function",
                        "function": {
                            "name": call.name,
                            "arguments": json.dumps(call.arguments, ensure_ascii=False),
                        },
                    }
                    for call in message.tool_calls
                ]
            converted.append(entry)
    return converted


def to_openai_tools(tools: Sequence[ToolSchema]) -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.parameters,
            },
        }
        for tool in tools
    ]


class OpenAIAdapter:
    """Chat Completions with function calling."""

    provider = "openai"

    def __init__(
        self,
        model_id: str,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        timeout: float = DEFAULT_TIMEOUT,
        client: Any | None = None,
    ) -> None:
        self.model_id = model_id
        self.base_url = base_url
        self._api_key = api_key
        self._max_tokens = max_tokens
        self._timeout = timeout
        self._client = client

    @property
    def client(self) -> Any:
        """The SDK client, constructed on first access."""
        if self._client is None:
            api_key = self._api_key or os.environ.get("OPENAI_API_KEY")
            if not api_key:
                raise MissingAPIKeyError(
                    "OPENAI_API_KEY is not set. Export it or put it in .env "
                    "(see .env.example); use --base-url for DeepSeek, GLM or another "
                    "OpenAI-compatible endpoint. The test suite never needs it."
                )
            from openai import OpenAI

            self._client = OpenAI(
                api_key=api_key,
                base_url=self.base_url or os.environ.get("OPENAI_BASE_URL") or None,
                timeout=self._timeout,
                # Gateways built for coding agents (e.g. OpenCode Go) ask clients to
                # identify themselves and to pin a stable session id per conversation
                # for routing and prompt caching. Harmless for any other endpoint.
                default_headers={
                    "User-Agent": "agent-safety-lab/0.1 (research harness)",
                    "x-opencode-session": f"agent-safety-lab-{uuid.uuid4()}",
                },
            )
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
        response = self.client.chat.completions.create(
            model=self.model_id,
            max_tokens=self._max_tokens,
            messages=to_openai_messages(messages, system),
            tools=to_openai_tools(tools),
        )
        choice = response.choices[0]
        message = choice.message
        calls = tuple(
            ToolCall(
                id=call.id,
                name=call.function.name,
                arguments=parse_arguments(call.function.arguments),
            )
            for call in (message.tool_calls or ())
        )
        return ModelTurn(
            text=(message.content or "").strip(),
            tool_calls=calls,
            stop_reason=str(getattr(choice, "finish_reason", None) or "end_turn"),
        )
