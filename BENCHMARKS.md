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

Latency budgeting tips:

- measure text-only chat routes separately from multimodal or document-review routes
- compare shadow-mode telemetry volume before and after enabling new route presets
- track release-over-release noise changes on the same route set before widening enforcement

## False-positive Rollout Guidance

Recommended rollout order:

1. Start with `preset: 'shadowFirst'`
2. Capture `report.telemetry` and `onTelemetry` output in structured logs
3. Add route-level overrides for high-risk flows such as admin, billing, exports, and tool-calling
4. Promote specific routes from shadow mode to blocking only after reviewing false-positive rates

Operational questions this should answer:

- What would have been blocked this week?
- Which routes trigger the most prompt-injection findings?
- Which features or workflows are producing the most noise?
- Which users or identity providers are associated with the most risky traffic?
- Which tenants or models show the highest concentration of severe findings?
- Which rules are most common before enforcement is turned on?
- Did the latest release increase alerts on the same route mix?

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
