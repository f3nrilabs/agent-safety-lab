"""Helpers shared by the tests (no fixtures, no network, no API keys)."""

from __future__ import annotations

from collections.abc import Sequence

from harness.adapters import ScriptedModel, ScriptedStep
from harness.agent import RunTranscript, run_scenario
from harness.protocol import ChatMessage
from harness.scenarios import PROJECT_ROOT, Scenario, load_scenario
from harness.scorer import Score, score_run
from harness.tools import ToolInvocation

INJECTION_SCENARIO = PROJECT_ROOT / "scenarios" / "injection" / "inj-web-hidden-comment-exfil.yaml"
FABRICATION_SCENARIO = PROJECT_ROOT / "scenarios" / "fabrication" / "fab-screenshot-error.yaml"

PAGE_URL = "https://login.example.test/session"


def load_injection_scenario() -> Scenario:
    return load_scenario(INJECTION_SCENARIO)


def load_fabrication_scenario() -> Scenario:
    return load_scenario(FABRICATION_SCENARIO)


def play(
    scenario: Scenario,
    steps: Sequence[ScriptedStep],
    *,
    defense: str = "none",
    max_turns: int = 8,
) -> tuple[ScriptedModel, RunTranscript, Score]:
    """Run a scenario against a scripted model and return model, transcript and score."""
    model = ScriptedModel(steps)
    transcript = run_scenario(scenario, model, defense=defense, max_turns=max_turns)
    return model, transcript, score_run(scenario, transcript)


def invocation(
    tool: str,
    arguments: dict[str, object] | None = None,
    *,
    available: bool = True,
    executed: bool = True,
    content: str = "",
) -> ToolInvocation:
    return ToolInvocation(
        tool=tool,
        arguments=dict(arguments or {}),
        available=available,
        executed=executed,
        content=content,
    )


def make_transcript(
    scenario: Scenario,
    *,
    invocations: Sequence[ToolInvocation] = (),
    tool_outputs: Sequence[str] = (),
    final_answer: str = "",
    defense: str = "none",
    provider: str = "scripted",
) -> RunTranscript:
    """A transcript with chosen invocations/outputs, for scorer unit tests."""
    messages: list[ChatMessage] = [ChatMessage(role="user", text=scenario.task)]
    messages.extend(ChatMessage(role="tool", text=output) for output in tool_outputs)
    messages.append(ChatMessage(role="assistant", text=final_answer))
    return RunTranscript(
        scenario_id=scenario.id,
        suite=scenario.suite,
        defense=defense,
        provider=provider,
        model_id="scripted-model",
        system_prompt="",
        task=scenario.task,
        messages=tuple(messages),
        invocations=tuple(invocations),
        side_effects=(),
        final_answer=final_answer,
        turns=1,
    )
