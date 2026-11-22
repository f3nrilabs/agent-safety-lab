"""Environment handling.

Keys come from the process environment only. A ``.env`` file, if present, is parsed by
this small loader (no python-dotenv) and its values are treated as defaults: a real
environment variable always wins and nothing is written back to disk.
"""

from __future__ import annotations

import os
from pathlib import Path

DEFAULT_ENV_FILE = Path(".env")


def parse_env_file(path: Path) -> dict[str, str]:
    """Parse a minimal ``KEY=VALUE`` file.

    Supports blank lines, ``#`` comments, optional ``export`` prefixes, single or double
    quotes around the value, and inline ``#`` comments after unquoted values.
    """
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not key or not key.replace("_", "").isalnum():
            continue
        value = value.strip()
        if value[:1] in {'"', "'"} and value[-1:] == value[:1] and len(value) >= 2:
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        values[key] = value
    return values


def load_env_file(path: Path | str | None = None) -> dict[str, str]:
    """Load ``.env`` defaults without overriding real environment variables.

    Returns the values that were applied.
    """
    source = Path(path) if path is not None else DEFAULT_ENV_FILE
    applied: dict[str, str] = {}
    for key, value in parse_env_file(source).items():
        if key in os.environ:
            continue
        os.environ[key] = value
        applied[key] = value
    return applied


def get_key(*names: str) -> str | None:
    """First non-empty value among ``names`` from the environment."""
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return None
