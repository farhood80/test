# AI-driven DDoS mitigation gateway

This repository contains a lightweight prototype for an **AI-driven DDoS mitigation gateway**.

## What it does

- Applies per-IP token-bucket rate limiting.
- Learns a moving baseline for global traffic (EWMA requests/second).
- Calculates a risk score per request using:
  - local rate-limit pressure,
  - global anomaly signal,
  - endpoint sensitivity.
- Returns one of three actions:
  - `allow`
  - `challenge` (e.g., CAPTCHA or proof-of-work)
  - `block` (with automatic IP blocklisting)

## Quick start

```bash
python -m pytest
```

Core implementation: `src/ddos_gateway.py`

Tests: `tests/test_gateway.py`
