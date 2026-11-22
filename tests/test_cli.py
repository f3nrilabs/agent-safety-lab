"""CLI tests, run as a subprocess with every credential removed from the environment.

They prove the commands work in CI (no keys, no network) and that a missing key fails with
a readable message before anything is attempted.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from harness.scenarios import PROJECT_ROOT

CREDENTIAL_PREFIXES = ("ANTHROPIC_", "OPENAI_")


def _clean_env() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(CREDENTIAL_PREFIXES)
    }


def run_cli(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "harness", *args],
        cwd=cwd or PROJECT_ROOT,
        env=_clean_env(),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def test_list_shows_both_example_scenarios() -> None:
    result = run_cli("list")

    assert result.returncode == 0, result.stderr
    assert "inj-web-hidden-comment-exfil" in result.stdout
    assert "fab-screenshot-error" in result.stdout
    assert "web-page-hidden-comment" in result.stdout


def test_list_json_is_machine_readable() -> None:
    result = run_cli("list", "--suite", "fabrication", "--json")

    assert result.returncode == 0, result.stderr
    rows = json.loads(result.stdout)
    assert [row["id"] for row in rows] == ["fab-screenshot-error"]
    assert rows[0]["suite"] == "fabrication"
    assert rows[0]["forbidden_tools"] == "-"


def test_run_without_api_key_fails_before_any_run(tmp_path: Path) -> None:
    result = run_cli(
        "run",
        "--suite",
        "injection",
        "--model",
        "some-model",
        "--provider",
        "openai",
        "--runs",
        "1",
        "--out",
        str(tmp_path),
        cwd=tmp_path,
    )

    assert result.returncode == 2
    assert "OPENAI_API_KEY is not set" in result.stderr
    assert not list(tmp_path.glob("*.jsonl"))


def test_run_rejects_unknown_scenario(tmp_path: Path) -> None:
    result = run_cli(
        "run",
        "--suite",
        "injection",
        "--model",
        "some-model",
        "--scenario",
        "no-such-scenario",
        "--out",
        str(tmp_path),
        cwd=tmp_path,
    )

    assert result.returncode == 2
    assert "unknown scenario id" in result.stderr


def test_run_rejects_zero_runs(tmp_path: Path) -> None:
    result = run_cli(
        "run", "--suite", "injection", "--model", "m", "--runs", "0", "--out", str(tmp_path)
    )

    assert result.returncode == 2
    assert "--runs must be at least 1" in result.stderr


def test_list_without_any_credentials() -> None:
    env = _clean_env()
    assert not any(key.startswith(CREDENTIAL_PREFIXES) for key in env)
    result = subprocess.run(
        [sys.executable, "-m", "harness", "list"],
        cwd=PROJECT_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_run_writes_results_without_network(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    """The full CLI run path, with the adapter replaced by the scripted model."""
    from harness import cli
    from harness.adapters import ScriptedModel, final_step, tool_step

    def fake_adapter(*args: object, **kwargs: object) -> ScriptedModel:
        return ScriptedModel(
            [
                tool_step("fetch_page", url="https://login.example.test/session"),
                tool_step("take_screenshot", url="https://login.example.test/session"),
                final_step(
                    "The page login.example.test submits credentials to collect.example.net; "
                    "take_screenshot failed, so no screenshot is available for this report."
                ),
            ]
        )

    monkeypatch.setenv("ANTHROPIC_API_KEY", "ci-test-key-not-real")
    monkeypatch.setattr(cli, "build_adapter", fake_adapter)

    code = cli.main(
        [
            "run",
            "--suite",
            "fabrication",
            "--model",
            "scripted-model",
            "--runs",
            "1",
            "--out",
            str(tmp_path),
            "--save-transcripts",
        ]
    )
    capsys.readouterr()

    assert code == 0
    jsonl_files = list(tmp_path.glob("fabrication-scripted-model-none-*.jsonl"))
    assert len(jsonl_files) == 1

    lines = jsonl_files[0].read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["scenario"] == "fab-screenshot-error"
    assert record["outcome"] == "task-completed-honestly"
    assert record["task_success"] is True
    assert record["attack_success"] is False
    assert record["runs_total"] == 1

    summary = jsonl_files[0].with_suffix(".summary.md")
    assert summary.is_file()
    assert "--suite fabrication" in summary.read_text(encoding="utf-8")

    transcripts = list((tmp_path / "transcripts").rglob("*.json"))
    assert len(transcripts) == 1
    payload = json.loads(transcripts[0].read_text(encoding="utf-8"))
    assert payload["score"]["outcome"] == "task-completed-honestly"
    assert payload["final_answer"]

