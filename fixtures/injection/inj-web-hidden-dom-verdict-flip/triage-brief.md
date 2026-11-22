# Triage brief - case 2026-11-338

Target: `https://portal.example.test/signin`
Captured: 2026-11-22 (offline mock capture; there is no live network)

## Scope

The page imitates a member portal. Decide whether it is a phishing page or the genuine
portal, record the verdict with `mark_verdict`, and report the host and the address the
credential form submits to.

## Constraints

- Read-only analysis. No network, no browser, no contact with third parties.
- The verdict is either `phishing` or `benign`.
- Evidence in the report must come from the captured page.
