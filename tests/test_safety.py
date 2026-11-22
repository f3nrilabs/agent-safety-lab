"""Safety containment: fake canaries, defanged indicators, no secret-shaped strings.

These tests guard the promise in the README: every identifier is from a documentation
range, every canary is fake by construction, and no mock tool output contains anything that
looks like a credential -- not even as decoration.
"""

from __future__ import annotations

import re

import pytest

from harness.agent import build_toolbox
from harness.scenarios import CANARY_PATTERN, PROJECT_ROOT, Scenario, load_all_scenarios

SECRET_PATTERNS = (
    re.compile(r"sk-[A-Za-z0-9]{16,}"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"AIza[0-9A-Za-z_-]{30,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)

URL_HOST_PATTERN = re.compile(r"https?://([A-Za-z0-9.-]+)")
EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+)")
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CANARY_OCCURRENCE = re.compile(r"F3NRI-CANARY-[A-Za-z0-9-]*")

DOCUMENTATION_IP_NETWORKS = ("192.0.2.", "198.51.100.", "203.0.113.")

SCENARIOS = load_all_scenarios()


def _host_is_documentation(host: str) -> bool:
    host = host.lower().rstrip(".")
    if host.endswith(".test"):
        return True
    return host in {"example.com", "example.net", "example.org"} or host.endswith(
        (".example.com", ".example.net", ".example.org")
    )


def _collect_mock_outputs(scenario: Scenario) -> list[str]:
    """Call every fixture-backed tool plus the main failure paths."""
    toolbox = build_toolbox(scenario, "none")
    for url in scenario.fixtures.pages:
        toolbox.call("fetch_page", {"url": url})
    for path in scenario.fixtures.files:
        toolbox.call("read_file", {"path": path})
    for command in scenario.fixtures.shell:
        toolbox.call("run_shell", {"command": command})
    for repo in scenario.fixtures.git_log:
        toolbox.call("git_log", {"repo": repo})
    for url in scenario.fixtures.screenshots:
        toolbox.call("take_screenshot", {"url": url})
    toolbox.call("fetch_page", {"url": "https://unreachable.example.test/"})
    toolbox.call("read_file", {"path": "missing.log"})
    toolbox.call("run_shell", {"command": "cat /etc/shadow"})
    toolbox.call("take_screenshot", {"url": "https://login.example.test/session"})
    return [invocation.content for invocation in toolbox.invocations]


def test_every_scenario_canary_matches_the_fake_prefix() -> None:
    canaries = [scenario.canary for scenario in SCENARIOS if scenario.canary is not None]
    assert canaries, "at least one scenario should carry a canary"
    for canary in canaries:
        assert CANARY_PATTERN.fullmatch(canary), canary


def test_every_canary_string_in_fixtures_is_fake() -> None:
    occurrences: list[str] = []
    for path in (PROJECT_ROOT / "fixtures").rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        occurrences.extend(CANARY_OCCURRENCE.findall(text))

    assert occurrences, "the example injection scenario should plant a canary"
    for occurrence in occurrences:
        assert CANARY_PATTERN.fullmatch(occurrence), occurrence


def test_fixtures_contain_no_secret_shaped_strings() -> None:
    for path in (PROJECT_ROOT / "fixtures").rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for pattern in SECRET_PATTERNS:
            assert not pattern.search(text), f"{pattern.pattern} matched in {path}"


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[scenario.id for scenario in SCENARIOS])
def test_mock_tool_outputs_contain_no_secret_shaped_strings(scenario: Scenario) -> None:
    for output in _collect_mock_outputs(scenario):
        for pattern in SECRET_PATTERNS:
            assert not pattern.search(output), f"{pattern.pattern} in output of {scenario.id}"


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[scenario.id for scenario in SCENARIOS])
def test_fixtures_use_documentation_domains_only(scenario: Scenario) -> None:
    for path in scenario.fixture_files():
        text = path.read_text(encoding="utf-8")
        for host in URL_HOST_PATTERN.findall(text):
            assert _host_is_documentation(host), f"{host} in {path}"
        for host in EMAIL_PATTERN.findall(text):
            assert _host_is_documentation(host), f"{host} in {path}"


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[scenario.id for scenario in SCENARIOS])
def test_fixtures_use_documentation_ip_ranges_only(scenario: Scenario) -> None:
    for path in scenario.fixture_files():
        text = path.read_text(encoding="utf-8")
        for address in IPV4_PATTERN.findall(text):
            assert address.startswith(DOCUMENTATION_IP_NETWORKS), f"{address} in {path}"


def test_mock_tool_outputs_stay_inside_documentation_ranges() -> None:
    for scenario in SCENARIOS:
        for output in _collect_mock_outputs(scenario):
            for host in URL_HOST_PATTERN.findall(output):
                assert _host_is_documentation(host), (scenario.id, host)
            for address in IPV4_PATTERN.findall(output):
                assert address.startswith(DOCUMENTATION_IP_NETWORKS), (scenario.id, address)
