"""A scripted fake model for tests: replays tool calls and a final answer, zero network.

It implements the same :class:`~harness.protocol.ModelAdapter` interface as the real
adapters, so the whole pipeline (system prompt, tool schemas, tool execution, transcript,
scoring) is exercised exactly as in a live run. It also records the prompts it received so
tests can assert on defenses.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from ..protocol import ChatMessage, ModelTurn, ToolCall, ToolSchema


@dataclass(frozen=True)
class ScriptedCall:
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ScriptedStep:
    """One scripted model turn: zero or more tool calls, plus optional text."""

    tool_calls: tuple[ScriptedCall, ...] = ()
    text: str = ""


def tool_step(name: str, **arguments: Any) -> ScriptedStep:
    """A turn that calls exactly one tool."""
    return ScriptedStep(tool_calls=(ScriptedCall(name=name, arguments=arguments),), text="")


def calls_step(*calls: ScriptedCall, text: str = "") -> ScriptedStep:
    """A turn that calls several tools at once."""
    return ScriptedStep(tool_calls=tuple(calls), text=text)


def final_step(text: str) -> ScriptedStep:
    """A turn with no tool calls, which ends the run."""
    return ScriptedStep(tool_calls=(), text=text)


class ScriptedModel:
    """Replays ``steps`` in order; once exhausted it returns an empty final answer."""

    provider = "scripted"

    def __init__(
        self,
        steps: Sequence[ScriptedStep],
        *,
        model_id: str = "scripted-model",
    ) -> None:
        self.model_id = model_id
        self._steps = tuple(steps)
        self._index = 0
        self._call_counter = 0
        self.system_prompts: list[str] = []
        self.seen_messages: list[tuple[ChatMessage, ...]] = []
        self.seen_tools: list[tuple[ToolSchema, ...]] = []

    @property
    def turns_played(self) -> int:
        return self._index

    @property
    def exhausted(self) -> bool:
        return self._index >= len(self._steps)

    def complete(
        self,
        *,
        system: str,
        messages: Sequence[ChatMessage],
        tools: Sequence[ToolSchema],
    ) -> ModelTurn:
        self.system_prompts.append(system)
        self.seen_messages.append(tuple(messages))
        self.seen_tools.append(tuple(tools))
        if self.exhausted:
            return ModelTurn(text="", stop_reason="end_turn")
        step = self._steps[self._index]
        self._index += 1
        calls: list[ToolCall] = []
        for scripted in step.tool_calls:
            self._call_counter += 1
            calls.append(
                ToolCall(
                    id=f"scripted-call-{self._call_counter}",
                    name=scripted.name,
                    arguments=dict(scripted.arguments),
                )
            )
        return ModelTurn(
            text=step.text,
            tool_calls=tuple(calls),
            stop_reason="tool_use" if calls else "end_turn",
        )
