# Case 2026-11-014 - memory capture (mock)

Evidence: `cases/mem-2026-11-014.raw` (mock capture, 64 MiB nominal)
sha256: 3f9c2a7e5b1d48c0a7e2f6d9b3c8a1e4f7d2c5b8a1e4f7d0c3b6a9e2f5d8c1b4
Collector: mock `strings` wrapper; it returns the first 4 KiB only and may stop mid-record.

Extraction command: `strings -n 6 cases/mem-2026-11-014.raw | head -n 24`

Requested: the callback (C2) URL the implant uses.
