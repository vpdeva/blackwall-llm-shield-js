# Benchmarks and Regression Notes

## Local Micro-benchmarks

Baseline captured on March 22, 2026 from the local development environment with 500 iterations:

- `guardModelRequest()` average latency: `0.043 ms`
- `OutputFirewall.inspect()` average latency: `0.011 ms`

These numbers are for short text-only prompts and responses. Real latency will increase when you add:

- retrieval grounding documents
- custom prompt detectors
- named-entity detection
- larger multimodal message payloads

## False-positive Rollout Guidance

Recommended rollout order:

1. Start with `preset: 'shadowFirst'`
2. Capture `report.telemetry` and `onTelemetry` output in structured logs
3. Add route-level overrides for high-risk flows such as admin, billing, exports, and tool-calling
4. Promote specific routes from shadow mode to blocking only after reviewing false-positive rates

## Regression Expectations

Current regression coverage includes:

- prompt-injection overrides
- system-prompt leakage attempts
- token and secret leakage
- Australian PII masking
- route-policy suppression
- custom prompt detectors
- provider adapter wrappers
- multimodal message-part masking

Run the regression suite with:

```bash
npm test
```
