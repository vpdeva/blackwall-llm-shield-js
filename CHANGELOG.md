# Changelog

## Unreleased

- Updated the default OWASP LLM coverage report and checked-in badge to reflect full built-in framework coverage across the OWASP LLM Top 10 2025 categories.

## 0.6.3

- Replaced the README coverage badge with a checked-in badge generated from the OWASP coverage report output and linked it to the implementation.
- Added a social preview SVG, a contributor-friendly good-first-issues section, and a comparison page covering Blackwall versus OpenAI moderation.

## 0.6.2

- Restructured the README hero section with badges, install commands, and a fast copy-paste guard example.

## 0.6.1

- Expanded npm package keywords for stronger discovery across guardrails, RAG security, auditing, and streaming firewall use cases

## 0.6.0

- Added threat-intel sync hooks, anomaly detection, telemetry replay, signed inspection attestation, and a streaming output firewall
- Added policy-config validation flow through the scorecard CLI and expanded enterprise change-management primitives
- Kept the new runtime slice aligned with Python while preserving the existing shield APIs

## 0.5.1

- Added file-backed corpus hardening for adversarial mutations and strengthened the edge build's built-in PII masking coverage
- Added explicit coverage paths for training data poisoning, improper output reliance, excessive agency, and overreliance in OWASP reporting
- Fixed tracker lifecycle so shared conversation history stays attached to the shield instance instead of falling back to per-request creation

## 0.5.0

- Added automatic multi-turn threat tracking by default, realistic OWASP coverage reporting, and automatic provenance stamping on guarded request/output paths
- Added richer plugin hooks for output scanning, retrieval inspection, and telemetry enrichment plus an end-to-end `protectZeroTrustModelCall()` helper
- Expanded adversarial mutation strategies, improved unicode de-obfuscation, and added a Node-compatible vault encryption fallback

## 0.4.0

- Replaced the default semantic scorer model with a jailbreak-focused Protect AI checkpoint and improved label mapping for security classifications
- Added a reversible `unvault()` API, `ConversationThreatTracker`, plugin registration via `shield.use(plugin)`, and an edge-safe entry point
- Added OWASP LLM coverage reporting, adversarial mutation helpers, prompt provenance tracking, and stronger grounding output metadata

## 0.2.1

- Added `CrossModelConsensusWrapper` for out-of-the-box cross-model safety verification
- Extended VaR breakers with tool-schema monetary value fields
- Added schema-derived digital twins from `ToolPermissionFirewall`
- Added `PolicyLearningLoop` for approval-history-based policy suggestions
- Added JWT-style passport tokens in `AgentIdentityRegistry`

## 0.3.0

- Added richer signed agent passports with capability manifests, lineage, trust scores, and PQC-ready crypto profile metadata
- Added `QuorumApprovalEngine`, `SovereignRoutingEngine`, simulation-mode digital twins with differential privacy noise, and explainable transparency reports
- Wired quorum approvals into tool gating and added trust-score degradation when agents repeatedly fall out of consensus

## 0.2.4

- Added wiki-ready example guides and linked them from the main README
- Updated repository hygiene with broader `.gitignore` coverage for local editor and build artifacts

## 0.2.3

- Promoted `@xenova/transformers` to a first-class dependency so the JS package installs as a more self-contained, standalone runtime
- Simplified the install docs to a single `npm install` path for production teams

## 0.2.2

- Added a globally applicable governance pack with data classification gates, provider routing policies, approval inbox models, upload quarantine workflows, retrieval trust scoring, outbound communication guards, compliance event bundles, and operational drift detection
- Expanded regulated-environment presets for government, banking, document intake, citizen services, and internal operations routes
- Added regression coverage for the new governance primitives and aligned enterprise rollout docs with the 0.2.x contract line

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
