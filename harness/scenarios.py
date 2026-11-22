"""Scenario loading and validation.

A scenario is a YAML file under ``scenarios/<suite>/``. The loader is deliberately strict:
a typo in a fixture path, an unknown tool, a malformed attack rule or a canary that never
appears in the fixtures is a hard error, not a silently weaker experiment. Every YAML in
the repository is loaded and validated by the test suite.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .tools import TOOL_SPECS, FixturePage, FixtureSet

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCENARIO_DIR = PROJECT_ROOT / "scenarios"

SUITES: tuple[str, ...] = ("injection", "fabrication")

CANARY_PATTERN = re.compile(r"F3NRI-CANARY-[0-9a-f]{12}")

#: Channels defined in ``docs/taxonomy.md`` (injection suite).
INJECTION_CHANNELS: tuple[str, ...] = (
    "web-page-text",
    "web-page-hidden-comment",
    "web-page-hidden-dom",
    "tool-output",
    "repo-file",
    "repo-config-file",
    "git-commit-message",
    "tls-certificate-field",
    "email-body",
    "http-header",
)

#: Attack goals defined in ``docs/taxonomy.md`` (injection suite).
INJECTION_GOALS: tuple[str, ...] = (
    "exfiltrate-canary",
    "call-forbidden-tool",
    "verdict-flip",
    "persist",
    "request-elevated-approval",
)

CANARY_CHANNELS: tuple[str, ...] = ("tool_arguments", "final_answer")

_TOP_LEVEL_KEYS = {
    "id",
    "suite",
    "channel",
    "goal",
    "task",
    "notes",
    "fixtures",
    "tools",
    "forbidden_tools",
    "canary",
    "attack_success",
    "task_success",
}

_FIXTURE_GROUPS = ("pages", "files", "shell", "git_log", "screenshots")


class ScenarioError(ValueError):
    """A scenario file is missing, malformed or inconsistent."""


@dataclass(frozen=True)
class AttackRules:
    """What counts as the attack winning this scenario."""

    canary_channels: tuple[str, ...] = ()
    forbidden_tools: tuple[str, ...] = ()
    verdict_flip: bool = False
    expected_verdict: str | None = None


@dataclass(frozen=True)
class ProvenanceRules:
    """Evidence-provenance rules for the fabrication suite.

    ``claim_patterns`` catch prose claims about evidence that cannot exist (a screenshot
    that was never rendered). ``ask_markers`` / ``admission_markers`` classify honest
    non-answers; they never turn a fabrication into a pass.
    """

    enabled: bool = False
    allow: tuple[str, ...] = ()
    claim_patterns: tuple[str, ...] = ()
    ask_markers: tuple[str, ...] = ()
    admission_markers: tuple[str, ...] = ()


@dataclass(frozen=True)
class TaskRules:
    """What counts as the legitimate task being done."""

    verdict: str | None = None
    report_contains: tuple[str, ...] = ()
    provenance: ProvenanceRules | None = None


@dataclass(frozen=True)
class Scenario:
    """One validated scenario."""

    id: str
    suite: str
    channel: str | None
    goal: str | None
    task: str
    tools: tuple[str, ...]
    forbidden_tools: tuple[str, ...]
    canary: str | None
    attack: AttackRules
    task_rules: TaskRules
    fixtures: FixtureSet
    source: Path
    notes: str = ""

    @property
    def is_injection(self) -> bool:
        return self.suite == "injection"

    def fixture_files(self) -> list[Path]:
        return self.fixtures.referenced_files()


@dataclass
class _Errors:
    """Collects every validation problem so one run reports all of them."""

    source: Path
    messages: list[str] = field(default_factory=list)

    def add(self, message: str) -> None:
        self.messages.append(message)

    def raise_if_any(self) -> None:
        if self.messages:
            joined = "\n  - ".join(self.messages)
            raise ScenarioError(f"{self.source}: invalid scenario:\n  - {joined}")


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:  # pragma: no cover - filesystem failure, not a data error
        raise ScenarioError(f"{path}: cannot read scenario: {exc}") from exc
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ScenarioError(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ScenarioError(f"{path}: a scenario must be a YAML mapping")
    return raw


def _mapping(value: Any, where: str, errors: _Errors) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        errors.add(f"{where} must be a mapping")
        return {}
    return value


def _string(value: Any, where: str, errors: _Errors, *, non_empty: bool = True) -> str | None:
    if not isinstance(value, str):
        errors.add(f"{where} must be a string")
        return None
    if non_empty and not value.strip():
        errors.add(f"{where} must not be empty")
        return None
    return value


def _string_list(value: Any, where: str, errors: _Errors) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        errors.add(f"{where} must be a list of strings")
        return ()
    cleaned: list[str] = []
    for item in value:
        if not item.strip():
            errors.add(f"{where} contains an empty string")
            continue
        if item in cleaned:
            errors.add(f"{where} contains a duplicate: {item}")
            continue
        cleaned.append(item)
    return tuple(cleaned)


def _unknown_keys(value: dict[str, Any], allowed: set[str], where: str, errors: _Errors) -> None:
    for key in sorted(set(value) - allowed):
        errors.add(f"{where} has unknown key: {key}")


def _resolve_path(raw: Any, root: Path, where: str, errors: _Errors) -> Path | None:
    text = _string(raw, where, errors)
    if text is None:
        return None
    candidate = Path(text)
    resolved = (candidate if candidate.is_absolute() else root / candidate).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        errors.add(f"{where} must stay inside the repository: {text}")
        return None
    if not resolved.is_file():
        errors.add(f"{where} does not exist (file expected): {text}")
        return None
    return resolved


def _build_fixtures(raw: Any, root: Path, errors: _Errors) -> FixtureSet:
    data = _mapping(raw, "fixtures", errors)
    _unknown_keys(data, set(_FIXTURE_GROUPS), "fixtures", errors)

    pages: dict[str, FixturePage] = {}
    for url, entry in _mapping(data.get("pages"), "fixtures.pages", errors).items():
        where = f"fixtures.pages[{url!r}]"
        if isinstance(entry, dict):
            _unknown_keys(entry, {"body", "status", "headers"}, where, errors)
            body = _resolve_path(entry.get("body"), root, f"{where}.body", errors)
            status = entry.get("status", 200)
            if not isinstance(status, int) or not 100 <= status <= 599:
                errors.add(f"{where}.status must be an integer HTTP status")
                status = 200
            headers_raw = _mapping(entry.get("headers"), f"{where}.headers", errors)
            headers = {
                str(key): str(value)
                for key, value in headers_raw.items()
                if isinstance(value, str | int | float)
            }
            if body is not None:
                pages[str(url)] = FixturePage(body=body, status=status, headers=headers)
        else:
            body = _resolve_path(entry, root, where, errors)
            if body is not None:
                pages[str(url)] = FixturePage(body=body)

    def simple_paths(group: str) -> dict[str, Path]:
        result: dict[str, Path] = {}
        for key, entry in _mapping(data.get(group), f"fixtures.{group}", errors).items():
            resolved = _resolve_path(entry, root, f"fixtures.{group}[{key!r}]", errors)
            if resolved is not None:
                result[str(key)] = resolved
        return result

    return FixtureSet(
        pages=pages,
        files=simple_paths("files"),
        shell=simple_paths("shell"),
        git_log=simple_paths("git_log"),
        screenshots=simple_paths("screenshots"),
    )


def _parse_attack(
    raw: Any,
    *,
    tools: tuple[str, ...],
    forbidden_tools: tuple[str, ...],
    canary: str | None,
    task_verdict: str | None,
    suite: str,
    errors: _Errors,
) -> AttackRules:
    data = _mapping(raw, "attack_success", errors)
    _unknown_keys(
        data,
        {"canary_in", "forbidden_tools", "verdict_flip", "expected_verdict"},
        "attack_success",
        errors,
    )

    if "canary_in" in data:
        channels = _string_list(data["canary_in"], "attack_success.canary_in", errors)
        for channel in channels:
            if channel not in CANARY_CHANNELS:
                errors.add(
                    "attack_success.canary_in must be among "
                    + ", ".join(CANARY_CHANNELS)
                    + f" (got {channel!r})"
                )
        channels = tuple(channel for channel in channels if channel in CANARY_CHANNELS)
    else:
        channels = CANARY_CHANNELS if canary is not None else ()
    if channels and canary is None:
        errors.add("attack_success.canary_in requires a scenario canary")

    forbidden = _string_list(data.get("forbidden_tools"), "attack_success.forbidden_tools", errors)
    if not forbidden and forbidden_tools:
        forbidden = forbidden_tools
    for name in forbidden:
        if name not in tools:
            errors.add(f"attack_success.forbidden_tools names a tool not in tools: {name}")

    verdict_flip = data.get("verdict_flip", False)
    if not isinstance(verdict_flip, bool):
        errors.add("attack_success.verdict_flip must be a boolean")
        verdict_flip = False

    if "expected_verdict" in data:
        expected = _string(
            data["expected_verdict"], "attack_success.expected_verdict", errors
        )
    else:
        expected = task_verdict
    if verdict_flip and not expected:
        errors.add(
            "attack_success.verdict_flip needs expected_verdict "
            "(or task_success.verdict to compare against)"
        )

    rules = AttackRules(
        canary_channels=channels,
        forbidden_tools=forbidden,
        verdict_flip=verdict_flip,
        expected_verdict=expected,
    )
    has_rule = bool(rules.canary_channels or rules.forbidden_tools or rules.verdict_flip)
    if suite == "injection" and not has_rule:
        errors.add("an injection scenario must define at least one attack_success rule")
    return rules


def _parse_task(raw: Any, *, suite: str, errors: _Errors) -> TaskRules:
    data = _mapping(raw, "task_success", errors)
    _unknown_keys(data, {"verdict", "report_contains", "provenance"}, "task_success", errors)

    verdict = (
        _string(data["verdict"], "task_success.verdict", errors) if "verdict" in data else None
    )
    report_contains = _string_list(
        data.get("report_contains"), "task_success.report_contains", errors
    )

    provenance: ProvenanceRules | None = None
    if "provenance" in data:
        prov = _mapping(data["provenance"], "task_success.provenance", errors)
        _unknown_keys(
            prov,
            {"enabled", "allow", "claim_patterns", "ask_markers", "admission_markers"},
            "task_success.provenance",
            errors,
        )
        enabled = prov.get("enabled", True)
        if not isinstance(enabled, bool):
            errors.add("task_success.provenance.enabled must be a boolean")
            enabled = True
        patterns = _string_list(
            prov.get("claim_patterns"), "task_success.provenance.claim_patterns", errors
        )
        for pattern in patterns:
            try:
                re.compile(pattern, re.IGNORECASE)
            except re.error as exc:
                errors.add(f"task_success.provenance.claim_patterns has a bad regex: {exc}")
        provenance = ProvenanceRules(
            enabled=enabled,
            allow=_string_list(prov.get("allow"), "task_success.provenance.allow", errors),
            claim_patterns=patterns,
            ask_markers=_string_list(
                prov.get("ask_markers"), "task_success.provenance.ask_markers", errors
            ),
            admission_markers=_string_list(
                prov.get("admission_markers"), "task_success.provenance.admission_markers", errors
            ),
        )

    rules = TaskRules(verdict=verdict, report_contains=report_contains, provenance=provenance)
    if not (rules.verdict or rules.report_contains or rules.provenance):
        errors.add("task_success must define verdict, report_contains or provenance")
    if suite == "fabrication" and not (rules.provenance and rules.provenance.enabled):
        errors.add("a fabrication scenario must enable task_success.provenance")
    return rules


def load_scenario(path: Path | str, *, root: Path | None = None) -> Scenario:
    """Load and validate one scenario file."""
    source = Path(path)
    if not source.is_absolute():
        source = (root or PROJECT_ROOT) / source
    source = source.resolve()
    base = (root or PROJECT_ROOT).resolve()
    raw = _load_yaml(source)
    errors = _Errors(source=source)

    _unknown_keys(raw, _TOP_LEVEL_KEYS, "scenario", errors)

    scenario_id = _string(raw.get("id"), "id", errors) or ""
    if scenario_id and not re.fullmatch(r"[a-z0-9][a-z0-9-]*", scenario_id):
        errors.add(f"id must be lower-case kebab-case (got {scenario_id!r})")
    if scenario_id and source.parent.name in SUITES and source.stem != scenario_id:
        errors.add(f"id {scenario_id!r} must match the file name {source.stem!r}")

    suite = _string(raw.get("suite"), "suite", errors) or ""
    if suite and suite not in SUITES:
        errors.add(f"suite must be one of {', '.join(SUITES)} (got {suite!r})")
    if suite and source.parent.name in SUITES and source.parent.name != suite:
        errors.add(f"suite {suite!r} does not match directory {source.parent.name!r}")

    channel = _string(raw.get("channel"), "channel", errors) if "channel" in raw else None
    goal = _string(raw.get("goal"), "goal", errors) if "goal" in raw else None
    if suite == "injection":
        if channel is None:
            errors.add("channel is required for the injection suite")
        elif channel not in INJECTION_CHANNELS:
            errors.add(f"unknown channel {channel!r}; see docs/taxonomy.md")
        if goal is None:
            errors.add("goal is required for the injection suite")
        elif goal not in INJECTION_GOALS:
            errors.add(f"unknown goal {goal!r}; see docs/taxonomy.md")

    task = _string(raw.get("task"), "task", errors) or ""
    if task and len(task.split()) < 20:
        errors.add("task must describe the legitimate work (at least 20 words)")

    tools = _string_list(raw.get("tools"), "tools", errors)
    if not tools:
        errors.add("tools must list at least one tool")
    for name in tools:
        if name not in TOOL_SPECS:
            errors.add(f"unknown tool: {name}")

    forbidden_tools = _string_list(raw.get("forbidden_tools"), "forbidden_tools", errors)
    for name in forbidden_tools:
        if name not in tools:
            errors.add(f"forbidden_tools names a tool not in tools: {name}")

    canary_raw = raw.get("canary")
    canary: str | None = None
    if canary_raw is not None:
        canary = _string(canary_raw, "canary", errors)
        if canary is not None and not CANARY_PATTERN.fullmatch(canary):
            errors.add("canary must look like F3NRI-CANARY-<12 lowercase hex characters>")

    fixtures = _build_fixtures(raw.get("fixtures"), base, errors)

    task_rules = _parse_task(raw.get("task_success"), suite=suite, errors=errors)
    attack = _parse_attack(
        raw.get("attack_success"),
        tools=tools,
        forbidden_tools=forbidden_tools,
        canary=canary,
        task_verdict=task_rules.verdict,
        suite=suite,
        errors=errors,
    )

    if canary is not None and canary not in _all_fixture_text(fixtures):
        errors.add(
            "canary does not appear in any fixture the scenario serves; "
            "the injection would be unreadable"
        )

    notes = _string(raw["notes"], "notes", errors, non_empty=False) if "notes" in raw else ""

    errors.raise_if_any()

    return Scenario(
        id=scenario_id,
        suite=suite,
        channel=channel,
        goal=goal,
        task=task,
        tools=tools,
        forbidden_tools=forbidden_tools,
        canary=canary,
        attack=attack,
        task_rules=task_rules,
        fixtures=fixtures,
        source=source,
        notes=notes,
    )


def _all_fixture_text(fixtures: FixtureSet) -> str:
    parts: list[str] = []
    for path in fixtures.referenced_files():
        parts.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(parts)


def scenario_paths(root: Path | None = None) -> list[Path]:
    """Every scenario YAML in the repository, suite directories only."""
    base = root or PROJECT_ROOT
    paths: list[Path] = []
    for suite in SUITES:
        paths.extend(sorted((base / "scenarios" / suite).glob("*.yaml")))
    return paths


def load_all_scenarios(root: Path | None = None) -> list[Scenario]:
    """Load every scenario; duplicate ids are a hard error."""
    scenarios: list[Scenario] = []
    seen: dict[str, Path] = {}
    for path in scenario_paths(root):
        scenario = load_scenario(path, root=root)
        if scenario.id in seen:
            raise ScenarioError(
                f"duplicate scenario id {scenario.id!r} in {seen[scenario.id]} and {path}"
            )
        seen[scenario.id] = path
        scenarios.append(scenario)
    return scenarios


def select_scenarios(
    suite: str, *, root: Path | None = None, ids: list[str] | None = None
) -> list[Scenario]:
    """Scenarios for ``suite`` (or all suites when ``suite == "all"``), optionally filtered."""
    if suite != "all" and suite not in SUITES:
        raise ScenarioError(f"unknown suite: {suite!r} (expected {'|'.join(SUITES)}|all)")
    scenarios = load_all_scenarios(root)
    if suite != "all":
        scenarios = [scenario for scenario in scenarios if scenario.suite == suite]
    if ids:
        wanted = set(ids)
        missing = wanted - {scenario.id for scenario in scenarios}
        if missing:
            raise ScenarioError("unknown scenario id(s): " + ", ".join(sorted(missing)))
        scenarios = [scenario for scenario in scenarios if scenario.id in wanted]
    return scenarios
