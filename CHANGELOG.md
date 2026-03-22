# Changelog

## 0.2.0

- Added `ValueAtRiskCircuitBreaker` for high-value tool/action thresholds with session revocation and MFA-style escalation flags
- Added `ShadowConsensusAuditor` integration in tool gating for logic-conflict review on high-impact actions
- Added `DigitalTwinOrchestrator` for mock tool sandboxes and pre-production twin testing
- Added `suggestPolicyOverride()` for self-healing policy tuning suggestions after approved false positives
- Added signed agent passports in `AgentIdentityRegistry`

## 0.1.9

- Added enterprise telemetry enrichment with SSO/user attribution on emitted events and audit records
- Added Power BI-friendly record builders and exporter hooks for telemetry pipelines
- Expanded operational summaries to break down findings by user and identity provider

## 0.1.8

- Expanded enterprise rollout guidance for controlled pilots, internal shield wrappers, and false-positive tuning
- Added clearer Next.js App Router and Gemini adoption guidance in the main docs
- Improved telemetry and benchmarking docs to focus on route-level operator reporting and release-noise review

## 0.1.7

- Added workflow-specific presets for planner, document-review, RAG-search, and tool-calling routes
- Added `protectJsonModelCall()` plus JSON parsing helpers for strict structured-output pipelines
- Improved Gemini adapter handling for system instructions and multimodal message parts
- Expanded operator telemetry summaries with feature grouping, noisiest routes, and weekly block estimates

## 0.1.6

- Added production-ready telemetry summaries grouped by route, tenant, model, policy outcome, and top rules
- Added first-class TypeScript declarations for the main package and subpath exports
- Fixed scoped package import examples and improved Next.js-native guidance

## 0.1.5

- Added route-level operational telemetry summaries for easier rollout visibility
- Added stronger rollout presets for RAG-safe and agent-tool workflows
- Expanded enterprise-oriented rollout docs around provider coverage, observability, and control-plane usage

## 0.1.4

- Added richer multimodal message-part normalization and masking
- Added provider adapters and stable wrapper guidance as first-class release docs
- Added migration notes, benchmark notes, and rollout guidance for false-positive tuning
- Expanded route-level and domain-level policy documentation for RAG and agent workflows

## 0.1.0

- Initial public release
- Sensitive-data masking
- Prompt-injection detection
- Output firewall
- Tool permission firewall
- Retrieval sanitizer
- Audit trail
- Policy packs
- Canary tokens
- Dashboard helpers
- Red-team eval harness
