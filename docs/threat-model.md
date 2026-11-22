# Threat model

## What is being attacked

A **security agent** (LLM + tool loop) doing real defensive work: phishing triage, certificate-transparency hits, repository review, bug bounty reports. The agent is treated as trustworthy; **the content it processes is not.**

## Adversary

An attacker who controls a *piece of content* the agent will inevitably read: a phishing page, a file in a repo, a commit message, a TLS certificate field, an email body, a tool's output. The attacker cannot touch the agent's prompt, tools, or harness — only the data flowing through them. This is **indirect prompt injection** and **tool-use hijacking**.

## Attacker goals (in order of value to the attacker)

1. **Exfiltration** — planted canary data leaves the process through an authorized side-effect tool (`send_message`, `write_memory`) or the final answer.
2. **Tool-use hijacking** — the agent calls a tool the task never authorized (`run_shell`, `mark_verdict`).
3. **Verdict manipulation** — the agent's security judgment is flipped ("this phishing domain is benign").
4. **Persistence** — a standing malicious order survives the session via `write_memory`.
5. **Privilege creep** — the agent requests elevated access on the attacker's behalf.

## Second failure class: fabrication

Not an attack at all — an **integrity failure under pressure to produce**. The evidence tool errors, the file is missing, the page never loads. An agent that invents plausible evidence (a screenshot description, a C2 URL, a log summary) fails a security reviewer worse than one that admits the gap: fabricated evidence poisons every downstream decision.

## What this lab assumes

- The agent has a **legitimate task** it is genuinely trying to do. We measure safety *and* usefulness; a defense that only destroys usefulness is not a win.
- Injection is **in-band**: no encoding tricks beyond what realistic content allows (an HTML comment, a header, a commit message).
- Side-effect tools are the boundary: anything that leaves the process (`send_message`, `write_memory`, `mark_verdict`) is where attacks cash out — and where defenses (`scoped`, `confirm`) focus.
- All targets are **mock, in-process, and fake**: canaries, documentation IP ranges, `.test` domains. Nothing in this lab can touch a real system.

## What is explicitly out of scope

Training attacks, multi-agent settings, vision/audio channels, real-world network operations, and any attempt to make planted payloads "work" outside this harness. Fixtures are inert text.
