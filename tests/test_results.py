"""Result writing: JSONL shape, file naming, summary contents."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from support import PAGE_URL, make_transcript, play

from harness.adapters import final_step, tool_step
from harness.results import (
    EXCERPT_CHARS,
    RESULT_FIELDS,
    BatchWriter,
    batch_path,
    build_record,
    excerpt,
    model_slug,
)
from harness.scenarios import Scenario
from harness.scorer import Score


def _run_once(scenario: Scenario):
    steps = [
        tool_step("fetch_page", url=PAGE_URL),
        final_step(
            "The host login.example.test is phishing; the form posts to collect.example.net."
        ),
    ]
    _, transcript, score = play(scenario, steps)
    return transcript, score


def test_model_slug_and_batch_path(tmp_path: Path) -> None:
    assert model_slug("Claude Sonnet 4.5") == "claude-sonnet-4-5"
    assert model_slug("deepseek/deepseek-chat") == "deepseek-deepseek-chat"
    assert model_slug("///") == "model"
    path = batch_path(tmp_path, "injection", "glm-4.6", "boundary", "2026-11-23T12:00:00Z")
    assert path.name == "injection-glm-4-6-boundary-20261123.jsonl"


def test_excerpt_is_single_line_and_bounded() -> None:
    assert excerpt("a\nb   c") == "a b c"
    long_text = "x" * (EXCERPT_CHARS + 50)
    result = excerpt(long_text)
    assert len(result) == EXCERPT_CHARS
    assert result.endswith("…")


def test_record_has_the_documented_fields(injection_scenario: Scenario) -> None:
    transcript, score = _run_once(injection_scenario)
    record = build_record(transcript, score, run=1, runs_total=3, date="2026-11-23T12:00:00Z")

    assert tuple(record) == RESULT_FIELDS
    assert record["scenario"] == "inj-web-hidden-comment-exfil"
    assert record["suite"] == "injection"
    assert record["defense"] == "none"
    assert record["run"] == 1
    assert record["runs_total"] == 3
    assert record["attack_success"] is False
    assert record["task_success"] is False  # no mark_verdict in this transcript
    assert record["base_url"] == ""
    assert record["final_answer_excerpt"].startswith("The host login.example.test")


def test_record_keeps_base_url_for_openai_runs(fabrication_scenario: Scenario) -> None:
    transcript = make_transcript(fabrication_scenario, provider="openai")
    score = Score(
        attack_success=False,
        attack_signal="",
        task_success=False,
        task_signal="admitted_failure",
        outcome="admitted-failure",
    )
    record = build_record(
        transcript,
        score,
        run=2,
        runs_total=2,
        date="2026-11-23T12:00:00Z",
        base_url="https://api.deepseek.com",
    )

    assert record["model"] == "scripted-model"
    assert record["base_url"] == "https://api.deepseek.com"


def test_batch_writer_writes_jsonl_and_summary(
    injection_scenario: Scenario, tmp_path: Path
) -> None:
    transcript, score = _run_once(injection_scenario)
    writer = BatchWriter(
        tmp_path,
        suite="injection",
        model_id="claude-test",
        defense="none",
        date="2026-11-23T12:00:00Z",
    )
    record = build_record(transcript, score, run=1, runs_total=1, date=writer.date)
    writer.append(record)

    assert writer.path == tmp_path / "injection-claude-test-none-20261123.jsonl"
    lines = writer.path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert tuple(parsed) == RESULT_FIELDS

    summary = writer.write_summary("python -m harness run --suite injection --model claude-test")
    text = summary.read_text(encoding="utf-8")
    assert summary == writer.path.with_suffix(".summary.md")
    assert "python -m harness run --suite injection --model claude-test" in text
    assert "inj-web-hidden-comment-exfil" in text
    assert "| 1 | 0/1 | 0/1 |" in text
    assert "safe+useless" in text


def test_batch_writer_rejects_incomplete_records(tmp_path: Path) -> None:
    writer = BatchWriter(
        tmp_path, suite="injection", model_id="m", defense="none", date="2026-11-23T12:00:00Z"
    )
    with pytest.raises(ValueError, match="missing fields"):
        writer.append({"scenario": "x"})


def test_batch_writer_appends_without_truncating(
    injection_scenario: Scenario, tmp_path: Path
) -> None:
    transcript, score = _run_once(injection_scenario)
    writer = BatchWriter(
        tmp_path, suite="injection", model_id="m", defense="none", date="2026-11-23T12:00:00Z"
    )
    writer.append(build_record(transcript, score, run=1, runs_total=2, date=writer.date))
    writer.append(build_record(transcript, score, run=2, runs_total=2, date=writer.date))

    lines = writer.path.read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["run"] for line in lines] == [1, 2]
    assert len(writer.records) == 2
