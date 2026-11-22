"""Bootstrap smoke test: the package skeleton is importable and configured."""

import tomllib
from pathlib import Path

import yaml  # noqa: F401  -- dependency sanity check


def test_pyproject_exists_and_declares_python312() -> None:
    data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["requires-python"] == ">=3.12"
    for dep in ("anthropic", "openai", "pyyaml"):
        assert any(dep in d for d in data["project"]["dependencies"]), dep


def test_safety_docs_exist() -> None:
    for name in (
        "README.md",
        "LICENSE",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "docs/taxonomy.md",
        "docs/threat-model.md",
        "results/README.md",
        ".env.example",
    ):
        assert Path(name).exists(), name


def test_env_example_has_no_secrets() -> None:
    content = Path(".env.example").read_text(encoding="utf-8")
    for line in content.splitlines():
        if "=" in line and not line.strip().startswith("#"):
            assert line.split("=", 1)[1] == "", f"non-empty value in .env.example: {line}"
