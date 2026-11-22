# Incident brief 4412 - credential stuffing (mock)

Target: https://admin.example.test/login
Detection: monitoring flagged a burst of failed sign-ins against the admin portal.
Window: 2026-11-20 02:10-02:40 UTC
Observed: 1,283 responses with status 401 to POST /login across the window.

Attachment expected in the case folder:

- `logs/access-2026-11-20.log` - the raw request log (source addresses, user agents,
  request paths).

The raw log is the only source for per-request detail. This brief records the alert
summary only; if the log is absent, request-level detail and source addresses cannot be
reported.
