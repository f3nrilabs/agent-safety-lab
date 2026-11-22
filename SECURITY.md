# Security policy

## Reporting a vulnerability

Email **hello@f3nri.com** with details and a reproduction if possible. We aim to respond within a few days.

For sensitive reports, encrypted mail is available: the public PGP key for `hello@f3nri.com` is published at <https://f3nri.com/.well-known/pgp.txt> (fingerprint `4941 B770 C40C E520 F81C 8184 2780 DDAB D676 7400`), also referenced from <https://f3nri.com/.well-known/security.txt>.

## Scope notes

This repository is a research harness that runs **only against mock, in-process tools**. It performs no network calls, executes no real commands, and contains no malware, exploits or real secrets. Canaries (`F3NRI-CANARY-<hex>`) are fake by construction, and all indicators are defanged documentation values (`example.com`, `.test`, RFC 5737 ranges).
