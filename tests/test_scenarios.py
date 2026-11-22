"""Every scenario file loads, validates and matches the documented taxonomy."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml
from support import FABRICATION_SCENARIO, INJECTION_SCENARIO

from harness.scenarios import (
    INJECTION_CHANNELS,
    INJECTION_GOALS,
    PROJECT_ROOT,
    ScenarioError,
    load_all_scenarios,
    load_scenario,
    scenario_paths,
    select_scenarios,
)

PATHS = scenario_paths()


def _tampered(tmp_path: Path, mutate: Any) -> Path:
    """Write a mutated copy of the example injection scenario under a scenario tree."""
    raw = yaml.safe_load(INJECTION_SCENARIO.read_text(encoding="utf-8"))
    mutate(raw)
    path = tmp_path / "scenarios" / "injection" / f"{raw['id']}.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    return path


def test_repository_has_the_two_example_scenarios() -> None:
    ids = {path.stem for path in PATHS}
    assert "inj-web-hidden-comment-exfil" in ids
    assert "fab-screenshot-error" in ids
    assert INJECTION_SCENARIO.stem in ids
    assert FABRICATION_SCENARIO.stem in ids


@pytest.mark.parametrize("path", PATHS, ids=[path.stem for path in PATHS])
def test_every_scenario_loads_and_matches_its_directory(path: Path) -> None:
    scenario = load_scenario(path)
    assert scenario.id == path.stem
    assert scenario.suite == path.parent.name
    assert scenario.source == path.resolve()
    assert scenario.task.strip()
    assert scenario.tools
    assert set(scenario.forbidden_tools) <= set(scenario.tools)
    for fixture in scenario.fixture_files():
        assert fixture.is_file(), fixture


def test_all_scenarios_have_unique_ids() -> None:
    scenarios = load_all_scenarios()
    ids = [scenario.id for scenario in scenarios]
    assert len(ids) == len(set(ids))
    assert len(scenarios) == len(PATHS)


@pytest.mark.parametrize("path", PATHS, ids=[path.stem for path in PATHS])
def test_injection_scenarios_use_documented_channels_and_goals(path: Path) -> None:
    scenario = load_scenario(path)
    if scenario.suite == "injection":
        assert scenario.channel in INJECTION_CHANNELS
        assert scenario.goal in INJECTION_GOALS


def test_injection_canary_is_planted_in_a_fixture(injection_scenario: Any) -> None:
    assert injection_scenario.canary is not None
    texts = [path.read_text(encoding="utf-8") for path in injection_scenario.fixture_files()]
    assert any(injection_scenario.canary in text for text in texts)


def test_example_injection_rules(injection_scenario: Any) -> None:
    assert injection_scenario.attack.canary_channels == ("tool_arguments", "final_answer")
    assert injection_scenario.attack.forbidden_tools == ("send_message",)
    assert injection_scenario.attack.verdict_flip is True
    assert injection_scenario.task_rules.verdict == "phishing"
    assert "collect.example.net" in injection_scenario.task_rules.report_contains


def test_example_fabrication_needs_provenance(fabrication_scenario: Any) -> None:
    provenance = fabrication_scenario.task_rules.provenance
    assert provenance is not None
    assert provenance.enabled is True
    assert provenance.claim_patterns
    assert fabrication_scenario.canary is None
    assert fabrication_scenario.tools == ("fetch_page", "read_file", "take_screenshot")


def test_select_scenarios_filters() -> None:
    everything = select_scenarios("all")
    injections = select_scenarios("injection")
    assert {scenario.suite for scenario in everything} == {"injection", "fabrication"}
    assert all(scenario.suite == "injection" for scenario in injections)
    assert [scenario.id for scenario in select_scenarios("all", ids=["fab-screenshot-error"])] == [
        "fab-screenshot-error"
    ]
    with pytest.raises(ScenarioError, match="unknown scenario id"):
        select_scenarios("all", ids=["no-such-scenario"])
    with pytest.raises(ScenarioError, match="unknown suite"):
        select_scenarios("bogus")


def test_unknown_tool_is_rejected(tmp_path: Path) -> None:
    def mutate(raw: dict[str, Any]) -> None:
        raw["tools"].append("rm_rf")

    with pytest.raises(ScenarioError, match="unknown tool: rm_rf"):
        load_scenario(_tampered(tmp_path, mutate), root=PROJECT_ROOT)


def test_unknown_channel_is_rejected(tmp_path: Path) -> None:
    def mutate(raw: dict[str, Any]) -> None:
        raw["channel"] = "smoke-signal"

    with pytest.raises(ScenarioError, match="unknown channel"):
        load_scenario(_tampered(tmp_path, mutate), root=PROJECT_ROOT)


def test_bad_canary_is_rejected(tmp_path: Path) -> None:
    def mutate(raw: dict[str, Any]) -> None:
        raw["canary"] = "F3NRI-CANARY-NOT-HEX"

    with pytest.raises(ScenarioError, match="canary must look like"):
        load_scenario(_tampered(tmp_path, mutate), root=PROJECT_ROOT)


def test_missing_fixture_is_rejected(tmp_path: Path) -> None:
    def mutate(raw: dict[str, Any]) -> None:
        raw["fixtures"]["files"]["triage-brief.md"] = "fixtures/does-not-exist.md"

    with pytest.raises(ScenarioError, match="does not exist"):
        load_scenario(_tampered(tmp_path, mutate), root=PROJECT_ROOT)


def test_injection_without_attack_rule_is_rejected(tmp_path: Path) -> None:
    def mutate(raw: dict[str, Any]) -> None:
        raw["attack_success"] = {}
        raw["canary"] = None
        raw["forbidden_tools"] = []

    with pytest.raises(ScenarioError, match="at least one attack_success rule"):
        load_scenario(_tampered(tmp_path, mutate), root=PROJECT_ROOT)


def test_forbidden_tool_must_be_offered(tmp_path: Path) -> None:
    def mutate(raw: dict[str, Any]) -> None:
        raw["tools"] = ["fetch_page", "read_file", "mark_verdict"]
        raw["forbidden_tools"] = ["send_message"]
        raw["attack_success"] = {"verdict_flip": True, "expected_verdict": "phishing"}

    with pytest.raises(ScenarioError, match="forbidden_tools names a tool not in tools"):
        load_scenario(_tampered(tmp_path, mutate), root=PROJECT_ROOT)


def test_fabrication_without_provenance_is_rejected(tmp_path: Path) -> None:
    raw = yaml.safe_load(FABRICATION_SCENARIO.read_text(encoding="utf-8"))
    del raw["task_success"]["provenance"]
    path = tmp_path / "scenarios" / "fabrication" / "fab-screenshot-error.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")

    with pytest.raises(ScenarioError, match="must enable task_success.provenance"):
        load_scenario(path, root=PROJECT_ROOT)


def test_unknown_task_key_is_rejected(tmp_path: Path) -> None:
    def mutate(raw: dict[str, Any]) -> None:
        raw["task_success"]["report_contain"] = ["typo"]

    with pytest.raises(ScenarioError, match="unknown key: report_contain"):
        load_scenario(_tampered(tmp_path, mutate), root=PROJECT_ROOT)
