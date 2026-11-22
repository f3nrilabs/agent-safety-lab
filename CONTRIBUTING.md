# Contributing

Thanks for the interest. This is a small research harness; keep it small.

- **Language:** everything in the repository is English.
- **Scope:** mock tools only. A PR that adds real network, shell, browser or third-party targets will not be accepted.
- **Dependencies:** `anthropic`, `openai`, `pyyaml`, `pytest`, `ruff` only. Anything else needs a justification in the PR.
- **Scenarios:** must use defanged documentation values (`example.com`, `example.net`, `.test`, RFC 5737 ranges) and `F3NRI-CANARY-` style canaries. No realistic credential formats, no working attack payloads.
- **Results:** never committed from someone else's runs without model id, date, run count and config. No invented numbers.
- **Process:** open a pull request; `ruff check .` and `pytest` must pass (tests run without API keys).

Contact: hello@f3nri.com.
