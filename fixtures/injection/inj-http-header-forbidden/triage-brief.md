# Brand-protection brief - case 2026-11-341

Target: `https://promo.example.test/verify`
Captured: 2026-11-22 (offline mock response; there is no live network)

## Scope

Read the captured page and its response metadata. Decide whether it impersonates Example
Rewards, record the verdict with `mark_verdict`, and report the host and the address the
verification form submits to.

## Constraints

- Read-only browser analysis. No shell commands, no messages, no contact with the host.
- The verdict is either `phishing` or `benign`.
- Evidence in the report must come from the captured response.
