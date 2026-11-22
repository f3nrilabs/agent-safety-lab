"""Command line interface: ``python -m harness run ...`` and ``python -m harness list``.

Keys are read from the environment only. If a ``.env`` file sits in the working directory
it is parsed by :mod:`harness.env` and used as a default source; real environment variables
always win. A missing key produces a clear error before any run starts.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from dataclasses import asdict
from pathlib import Path

from . import __version__
from .adapters import PROVIDERS, build_adapter
from .agent import MAX_TURNS, RunTranscript, run_scenario
from .defenses import DEFENSES
from .env import get_key, load_env_file
from .protocol import AdapterError
from .results import BatchWriter, build_record, utc_now
from .scenarios import SUITES, Scenario, ScenarioError, select_scenarios
from .scorer import Score, score_run

PROVIDER_KEYS = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m harness",
        description=(
            "Mock-tool safety scenarios for tool-using security agents. "
            "No real shell, network or browser is involved."
        ),
    )
    parser.add_argument("--version", action="version", version=f"agent-safety-lab {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="list scenarios")
    list_parser.add_argument("--suite", choices=(*SUITES, "all"), default="all")
    list_parser.add_argument("--json", action="store_true", help="machine-readable output")

    run_parser = subparsers.add_parser("run", help="run scenarios against a model")
    run_parser.add_argument(
        "--suite", choices=(*SUITES, "all"), required=True, help="which suite to run"
    )
    run_parser.add_argument("--model", required=True, help="exact model id passed to the API")
    run_parser.add_argument("--runs", type=int, default=1, help="runs per scenario (default 1)")
    run_parser.add_argument(
        "--defense", choices=DEFENSES, default="none", help="defense under test (default none)"
    )
    run_parser.add_argument(
        "--provider", choices=PROVIDERS, default="anthropic", help="adapter to use"
    )
    run_parser.add_argument(
        "--base-url",
        default=None,
        help="OpenAI-compatible endpoint (DeepSeek, GLM, ...); openai provider only",
    )
    run_parser.add_argument("--out", default="results", help="results directory (default results)")
    run_parser.add_argument(
        "--max-turns",
        type=int,
        default=MAX_TURNS,
        help=f"model turns per run (default {MAX_TURNS})",
    )
    run_parser.add_argument(
        "--scenario",
        action="append",
        default=None,
        metavar="ID",
        help="limit the run to specific scenario id(s); repeatable",
    )
    run_parser.add_argument(
        "--save-transcripts",
        action="store_true",
        help="write full transcripts under <out>/transcripts/ (local only)",
    )
    return parser


def _scenario_rows(scenarios: list[Scenario]) -> list[dict[str, str]]:
    return [
        {
            "id": scenario.id,
            "suite": scenario.suite,
            "channel": scenario.channel or "-",
            "goal": scenario.goal or "-",
            "canary": scenario.canary or "-",
            "tools": ",".join(scenario.tools),
            "forbidden_tools": ",".join(scenario.forbidden_tools) or "-",
        }
        for scenario in scenarios
    ]


def cmd_list(args: argparse.Namespace) -> int:
    scenarios = select_scenarios(args.suite)
    rows = _scenario_rows(scenarios)
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    if not rows:
        print("no scenarios found")
        return 0
    headers = ("id", "suite", "channel", "goal", "forbidden_tools")
    widths = {header: len(header) for header in headers}
    for row in rows:
        for header in headers:
            widths[header] = max(widths[header], len(row[header]))
    print("  ".join(header.ljust(widths[header]) for header in headers))
    print("  ".join("-" * widths[header] for header in headers))
    for row in rows:
        print("  ".join(row[header].ljust(widths[header]) for header in headers))
    return 0


def _require_key(provider: str, api_key: str | None) -> str | None:
    """Return the key, or print the actionable error and return ``None``."""
    if api_key:
        return api_key
    name = PROVIDER_KEYS[provider]
    print(
        f"error: {name} is not set. Export it, or put it in .env (see .env.example). "
        "The test suite and `list` never need a key.",
        file=sys.stderr,
    )
    return None


def _transcript_payload(
    transcript: RunTranscript, score: Score, *, run: int, runs_total: int
) -> dict[str, object]:
    payload = asdict(transcript)
    payload["run"] = run
    payload["runs_total"] = runs_total
    payload["score"] = score.as_row()
    return payload


def cmd_run(args: argparse.Namespace, argv: list[str]) -> int:
    if args.runs < 1:
        print("error: --runs must be at least 1", file=sys.stderr)
        return 2
    if args.max_turns < 1:
        print("error: --max-turns must be at least 1", file=sys.stderr)
        return 2

    load_env_file()
    try:
        scenarios = select_scenarios(args.suite, ids=args.scenario)
    except ScenarioError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not scenarios:
        print(f"error: no scenarios for suite {args.suite!r}", file=sys.stderr)
        return 2

    api_key = get_key(PROVIDER_KEYS[args.provider])
    if _require_key(args.provider, api_key) is None:
        return 2

    base_url = None
    if args.provider == "openai":
        base_url = args.base_url or os.environ.get("OPENAI_BASE_URL") or None

    adapter = build_adapter(args.provider, args.model, base_url=base_url, api_key=api_key)
    date = utc_now()
    writers: dict[str, BatchWriter] = {}
    command = "python -m harness " + shlex.join(argv)

    for scenario in scenarios:
        writer = writers.get(scenario.suite)
        if writer is None:
            writer = BatchWriter(
                args.out,
                suite=scenario.suite,
                model_id=args.model,
                defense=args.defense,
                date=date,
            )
            writers[scenario.suite] = writer
        for run_index in range(1, args.runs + 1):
            try:
                transcript = run_scenario(
                    scenario, adapter, defense=args.defense, max_turns=args.max_turns
                )
            except AdapterError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
            score = score_run(scenario, transcript)
            writer.append(
                build_record(
                    transcript,
                    score,
                    run=run_index,
                    runs_total=args.runs,
                    date=date,
                    base_url=base_url,
                )
            )
            print(
                f"{scenario.id} run {run_index}/{args.runs}: turns={transcript.turns} "
                f"attack={score.attack_success} task={score.task_success} "
                f"outcome={score.outcome}"
            )
            if args.save_transcripts:
                _write_transcript(
                    Path(args.out) / "transcripts" / writer.path.stem,
                    transcript,
                    score,
                    run_index,
                    args.runs,
                )

    for writer in writers.values():
        summary = writer.write_summary(command)
        print(f"wrote {writer.path}")
        print(f"wrote {summary}")
    return 0


def _write_transcript(
    directory: Path,
    transcript: RunTranscript,
    score: Score,
    run_index: int,
    runs_total: int,
) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{transcript.scenario_id}-run{run_index}.json"
    payload = _transcript_payload(transcript, score, run=run_index, runs_total=runs_total)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(arguments)
    try:
        if args.command == "list":
            return cmd_list(args)
        return cmd_run(args, arguments)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except ScenarioError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
