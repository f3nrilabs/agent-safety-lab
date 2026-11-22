"""Shared pytest fixtures.

The autouse environment fixture removes every credential: the suite must pass with no keys
set at all, and a test that accidentally needed one should fail loudly.
"""

from __future__ import annotations

import pytest
from support import load_fabrication_scenario, load_injection_scenario

from harness.scenarios import Scenario

CREDENTIAL_VARS = (
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "OPENAI_ORG_ID",
    "OPENAI_PROJECT",
)


@pytest.fixture(autouse=True)
def no_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in CREDENTIAL_VARS:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(scope="session")
def injection_scenario() -> Scenario:
    return load_injection_scenario()


@pytest.fixture(scope="session")
def fabrication_scenario() -> Scenario:
    return load_fabrication_scenario()
