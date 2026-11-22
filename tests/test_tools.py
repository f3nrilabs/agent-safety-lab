"""Mock tool behaviour: fixtures only, honest errors, nothing executed."""

from __future__ import annotations

import pytest
from support import PAGE_URL

from harness.agent import build_toolbox
from harness.scenarios import Scenario
from harness.tools import TOOL_ORDER, TOOL_SPECS, FixtureSet, MockToolbox


def test_tool_schemas_are_well_formed() -> None:
    for name, spec in TOOL_SPECS.items():
        assert spec.name == name
        assert spec.description
        assert spec.parameters["type"] == "object"
        assert isinstance(spec.parameters["properties"], dict)
        for required in spec.parameters["required"]:
            assert required in spec.parameters["properties"]


def test_toolbox_advertises_canonical_order(injection_scenario: Scenario) -> None:
    toolbox = build_toolbox(injection_scenario, "none")

    assert toolbox.tool_names == tuple(
        name for name in TOOL_ORDER if name in injection_scenario.tools
    )
    assert [schema.name for schema in toolbox.schemas()] == list(toolbox.tool_names)


def test_unknown_tool_name_is_a_construction_error() -> None:
    with pytest.raises(ValueError, match="unknown tool"):
        MockToolbox(FixtureSet(), ["fetch_page", "rm_rf"])


def test_fetch_page_serves_the_fixture(injection_scenario: Scenario) -> None:
    toolbox = build_toolbox(injection_scenario, "none")

    result = toolbox.call("fetch_page", {"url": PAGE_URL})

    assert result.ok is True
    assert result.content.startswith("HTTP/1.1 200 OK")
    assert "collect.example.net" in result.content
    assert "Example Credit Union" in result.content


def test_fetch_page_unknown_url_is_an_error(injection_scenario: Scenario) -> None:
    toolbox = build_toolbox(injection_scenario, "none")

    result = toolbox.call("fetch_page", {"url": "https://nowhere.example.test/"})

    assert result.ok is False
    assert result.detail == "fixture-missing"
    assert "no response for" in result.content


def test_read_file_serves_and_reports_missing(injection_scenario: Scenario) -> None:
    toolbox = build_toolbox(injection_scenario, "none")

    found = toolbox.call("read_file", {"path": "triage-brief.md"})
    missing = toolbox.call("read_file", {"path": "logs/access.log"})

    assert found.ok is True
    assert "case 2026-11-014" in found.content
    assert missing.ok is False
    assert missing.content == "read_file failed: file not found: logs/access.log"


def test_take_screenshot_errors_without_a_fixture(fabrication_scenario: Scenario) -> None:
    toolbox = build_toolbox(fabrication_scenario, "none")

    result = toolbox.call("take_screenshot", {"url": PAGE_URL})

    assert result.ok is False
    assert result.detail == "fixture-missing"
    assert "take_screenshot failed" in result.content
    assert "no image was produced" in result.content


def test_run_shell_never_executes_anything(injection_scenario: Scenario) -> None:
    toolbox = MockToolbox(injection_scenario.fixtures, list(TOOL_ORDER))

    result = toolbox.call("run_shell", {"command": "id"})

    assert result.ok is False
    assert "nothing was executed" in result.content


def test_git_log_reports_missing_repository(injection_scenario: Scenario) -> None:
    toolbox = MockToolbox(injection_scenario.fixtures, list(TOOL_ORDER))

    result = toolbox.call("git_log", {"repo": "some-repo"})

    assert result.ok is False
    assert "no fixture repository" in result.content


def test_missing_argument_is_rejected(injection_scenario: Scenario) -> None:
    toolbox = build_toolbox(injection_scenario, "none")

    result = toolbox.call("fetch_page", {})

    assert result.ok is False
    assert result.detail == "bad-arguments"
    assert "required argument: url" in result.content


def test_malformed_json_arguments_are_rejected(injection_scenario: Scenario) -> None:
    toolbox = build_toolbox(injection_scenario, "none")

    result = toolbox.call("fetch_page", {"_unparsed_arguments": "not json"})

    assert result.ok is False
    assert result.detail == "bad-arguments"
    assert "not valid JSON" in result.content


def test_side_effects_are_recorded_and_confined(injection_scenario: Scenario) -> None:
    toolbox = MockToolbox(injection_scenario.fixtures, list(TOOL_ORDER))

    sent = toolbox.call(
        "send_message", {"recipient": "soc-sync@example.net", "body": "case note"}
    )
    stored = toolbox.call("write_memory", {"key": "case", "value": "note"})
    verdict = toolbox.call("mark_verdict", {"verdict": "phishing", "rationale": "clone"})

    assert sent.ok and stored.ok and verdict.ok
    assert [effect.tool for effect in toolbox.side_effects] == [
        "send_message",
        "write_memory",
        "mark_verdict",
    ]
    for result in (sent, stored, verdict):
        assert "nothing left the process" in result.content or "mock store" in result.content
    assert len(toolbox.invocations) == 3
    assert all(invocation.executed for invocation in toolbox.invocations)
