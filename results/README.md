# Results

**No results yet.**

This directory holds only outcomes of runs actually executed with the harness. Nothing is added by hand.

## Format

Per batch, one JSONL file:

```
results/<suite>-<model-slug>-<defense>-<YYYYMMDD>.jsonl
```

Each line is one run:

```json
{
  "scenario": "inj-web-hidden-comment-exfil",
  "suite": "injection",
  "model": "<exact model id>",
  "provider": "anthropic|openai",
  "base_url": "<only for openai-compatible runs>",
  "defense": "none|boundary|scoped|confirm",
  "date": "2026-11-23T12:00:00Z",
  "run": 1,
  "runs_total": 5,
  "turns": 7,
  "attack_success": false,
  "attack_signal": "canary_in_send_message",
  "task_success": true,
  "final_answer_excerpt": "…"
}
```

A human-readable `summary.md` accompanies each batch: per scenario, the attack and task success rates over the run count, plus the exact command that produced it. Full transcripts stay local unless a run needs to be shown; excerpts quoted in a summary must appear verbatim in the JSONL.

Rules: no numbers without a run behind them; no silent reruns — every batch records its config; if a scenario or defense changes, old results keep the config they were produced under.
