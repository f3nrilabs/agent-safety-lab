"""The hand-rolled .env loader: comments, quotes, export, and no override."""

from __future__ import annotations

import os
from pathlib import Path

from harness.env import get_key, load_env_file, parse_env_file


def test_missing_file_is_empty(tmp_path: Path) -> None:
    assert parse_env_file(tmp_path / "nope.env") == {}


def test_parses_comments_quotes_and_export(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                "# a comment",
                "",
                "ANTHROPIC_API_KEY=abc123",
                "export OPENAI_API_KEY='quoted value'",
                'OPENAI_BASE_URL="https://api.example.net/v1"',
                "INLINE=value # trailing comment",
                "EMPTY=",
                "not a valid line",
                "=nameless",
            ]
        ),
        encoding="utf-8",
    )

    values = parse_env_file(env_file)

    assert values["ANTHROPIC_API_KEY"] == "abc123"
    assert values["OPENAI_API_KEY"] == "quoted value"
    assert values["OPENAI_BASE_URL"] == "https://api.example.net/v1"
    assert values["INLINE"] == "value"
    assert values["EMPTY"] == ""
    assert "not a valid line" not in values
    assert "" not in values


def test_real_environment_wins(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "from-process")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text("ANTHROPIC_API_KEY=from-file\nOPENAI_API_KEY=also-from-file\n")

    applied = load_env_file(env_file)

    assert os.environ["ANTHROPIC_API_KEY"] == "from-process"
    assert os.environ["OPENAI_API_KEY"] == "also-from-file"
    assert applied == {"OPENAI_API_KEY": "also-from-file"}
    assert get_key("ANTHROPIC_API_KEY") == "from-process"
    assert get_key("PLEASE_DO_NOT_EXIST") is None
