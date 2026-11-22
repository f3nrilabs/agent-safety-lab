"""Adapter tests: lazy clients, message translation, no network.

The SDK clients are replaced by tiny stubs, so these tests prove the translation layer
without a key and without a call.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from harness.adapters import (
    AnthropicAdapter,
    OpenAIAdapter,
    ScriptedModel,
    build_adapter,
    final_step,
    tool_step,
)
from harness.adapters.anthropic_adapter import to_anthropic_messages, to_anthropic_tools
from harness.adapters.openai_adapter import to_openai_messages, to_openai_tools
from harness.protocol import ChatMessage, MissingAPIKeyError, ToolCall
from harness.tools import TOOL_SPECS

FETCH_TOOL = TOOL_SPECS["fetch_page"]
TOOLS = [FETCH_TOOL]


def _conversation() -> list[ChatMessage]:
    return [
        ChatMessage(role="user", text="Investigate the page."),
        ChatMessage(
            role="assistant",
            text="Fetching.",
            tool_calls=(ToolCall(id="call-1", name="fetch_page", arguments={"url": "u"}),),
        ),
        ChatMessage(
            role="tool",
            text="HTTP/1.1 200 OK",
            tool_call_id="call-1",
            tool_name="fetch_page",
        ),
        ChatMessage(role="tool", text="error", tool_call_id="call-2", is_error=True),
    ]


class _StubAnthropic:
    def __init__(self, response: object) -> None:
        self.messages = self
        self.kwargs: dict[str, object] | None = None
        self._response = response

    def create(self, **kwargs: object) -> object:
        self.kwargs = kwargs
        return self._response


class _StubOpenAI:
    def __init__(self, response: object) -> None:
        self.chat = SimpleNamespace(completions=self)
        self.kwargs: dict[str, object] | None = None
        self._response = response

    def create(self, **kwargs: object) -> object:
        self.kwargs = kwargs
        return self._response


def test_anthropic_adapter_is_lazy_and_needs_a_key_only_on_use() -> None:
    adapter = AnthropicAdapter("claude-model-test")

    assert adapter.has_client is False
    with pytest.raises(MissingAPIKeyError, match="ANTHROPIC_API_KEY"):
        adapter.complete(
            system="s", messages=[ChatMessage(role="user", text="hi")], tools=TOOLS
        )


def test_openai_adapter_is_lazy_and_needs_a_key_only_on_use() -> None:
    adapter = OpenAIAdapter("deepseek-chat", base_url="https://api.deepseek.com")

    assert adapter.has_client is False
    with pytest.raises(MissingAPIKeyError, match="OPENAI_API_KEY"):
        adapter.complete(
            system="s", messages=[ChatMessage(role="user", text="hi")], tools=TOOLS
        )


def test_anthropic_message_translation_groups_tool_results() -> None:
    converted = to_anthropic_messages(_conversation())

    assert [message["role"] for message in converted] == ["user", "assistant", "user"]
    assistant_blocks = converted[1]["content"]
    assert assistant_blocks[0] == {"type": "text", "text": "Fetching."}
    assert assistant_blocks[1]["type"] == "tool_use"
    assert assistant_blocks[1]["input"] == {"url": "u"}
    results = converted[2]["content"]
    assert [block["tool_use_id"] for block in results] == ["call-1", "call-2"]
    assert results[1]["is_error"] is True
    assert to_anthropic_tools(TOOLS)[0]["input_schema"] == FETCH_TOOL.parameters


def test_openai_message_translation() -> None:
    converted = to_openai_messages(_conversation(), "system text")

    assert converted[0] == {"role": "system", "content": "system text"}
    assert converted[1] == {"role": "user", "content": "Investigate the page."}
    assert converted[2]["tool_calls"][0]["function"]["name"] == "fetch_page"
    assert json.loads(converted[2]["tool_calls"][0]["function"]["arguments"]) == {"url": "u"}
    assert converted[3] == {"role": "tool", "tool_call_id": "call-1", "content": "HTTP/1.1 200 OK"}
    assert to_openai_tools(TOOLS)[0]["function"]["parameters"] == FETCH_TOOL.parameters


def test_anthropic_completion_is_parsed() -> None:
    stub = _StubAnthropic(
        SimpleNamespace(
            stop_reason="tool_use",
            content=[
                SimpleNamespace(type="text", text="Fetching the page."),
                SimpleNamespace(
                    type="tool_use",
                    id="toolu_1",
                    name="fetch_page",
                    input={"url": "https://login.example.test/session"},
                ),
            ],
        )
    )
    adapter = AnthropicAdapter("claude-model-test", client=stub)

    turn = adapter.complete(system="be careful", messages=_conversation(), tools=TOOLS)

    assert turn.text == "Fetching the page."
    assert turn.tool_calls[0].id == "toolu_1"
    assert turn.tool_calls[0].arguments == {"url": "https://login.example.test/session"}
    assert turn.stop_reason == "tool_use"
    assert stub.kwargs is not None
    assert stub.kwargs["model"] == "claude-model-test"
    assert stub.kwargs["system"] == "be careful"
    assert stub.kwargs["tools"][0]["name"] == "fetch_page"


def test_openai_completion_is_parsed() -> None:
    stub = _StubOpenAI(
        SimpleNamespace(
            choices=[
                SimpleNamespace(
                    finish_reason="tool_calls",
                    message=SimpleNamespace(
                        content="Fetching.",
                        tool_calls=[
                            SimpleNamespace(
                                id="call_9",
                                function=SimpleNamespace(
                                    name="fetch_page",
                                    arguments='{"url": "https://login.example.test/session"}',
                                ),
                            )
                        ],
                    ),
                )
            ]
        )
    )
    adapter = OpenAIAdapter("glm-4-test", client=stub)

    turn = adapter.complete(system="be careful", messages=_conversation(), tools=TOOLS)

    assert turn.text == "Fetching."
    assert turn.tool_calls[0].arguments == {"url": "https://login.example.test/session"}
    assert turn.stop_reason == "tool_calls"
    assert stub.kwargs is not None
    assert stub.kwargs["messages"][0]["role"] == "system"


def test_openai_adapter_tolerates_malformed_argument_json() -> None:
    stub = _StubOpenAI(
        SimpleNamespace(
            choices=[
                SimpleNamespace(
                    finish_reason="tool_calls",
                    message=SimpleNamespace(
                        content=None,
                        tool_calls=[
                            SimpleNamespace(
                                id="call_1",
                                function=SimpleNamespace(name="fetch_page", arguments="{not json"),
                            )
                        ],
                    ),
                )
            ]
        )
    )
    adapter = OpenAIAdapter("glm-4-test", client=stub)

    turn = adapter.complete(system="s", messages=[], tools=TOOLS)

    assert turn.tool_calls[0].arguments == {"_unparsed_arguments": "{not json"}


def test_build_adapter_chooses_provider() -> None:
    assert isinstance(build_adapter("anthropic", "m"), AnthropicAdapter)
    openai_adapter = build_adapter("openai", "m", base_url="https://api.deepseek.com")
    assert isinstance(openai_adapter, OpenAIAdapter)
    assert openai_adapter.base_url == "https://api.deepseek.com"
    with pytest.raises(ValueError, match="unknown provider"):
        build_adapter("cohere", "m")


def test_scripted_model_protocol_surface() -> None:
    model = ScriptedModel([tool_step("fetch_page", url="u"), final_step("done")])

    first = model.complete(system="s", messages=[], tools=TOOLS)
    second = model.complete(system="s", messages=[], tools=TOOLS)
    third = model.complete(system="s", messages=[], tools=TOOLS)

    assert model.provider == "scripted"
    assert model.model_id == "scripted-model"
    assert first.tool_calls[0].name == "fetch_page"
    assert second.text == "done"
    assert second.tool_calls == ()
    assert third.text == ""
    assert model.exhausted is True
    assert model.turns_played == 2
    assert len(model.system_prompts) == 3
