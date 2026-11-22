"""agent-safety-lab: mock-tool scenarios for measuring security-agent failure modes.

Public surface for scripts and tests: load a scenario, run it against any adapter, score
the transcript. Nothing in this package touches a real shell, network or browser.
"""

from __future__ import annotations

from .agent import MAX_TURNS, RunTranscript, build_system_prompt, run_scenario
from .defenses import DEFENSES
from .scenarios import Scenario, ScenarioError, load_all_scenarios, load_scenario
from .scorer import Score, score_run

__version__ = "0.1.0"

__all__ = [
    "DEFENSES",
    "MAX_TURNS",
    "RunTranscript",
    "Scenario",
    "ScenarioError",
    "Score",
    "build_system_prompt",
    "load_all_scenarios",
    "load_scenario",
    "run_scenario",
    "score_run",
]
