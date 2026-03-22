export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

export interface MessagePart {
  type: string;
  text?: string;
  image_url?: string;
  file_id?: string;
  [key: string]: unknown;
}

export interface ShieldMessage {
  role: 'system' | 'user' | 'assistant';
  content: string | MessagePart[] | Record<string, unknown>;
  trusted?: boolean;
  contentParts?: MessagePart[];
}

export interface GuardResult {
  allowed: boolean;
  blocked: boolean;
  reason: string | null;
  messages: Array<ShieldMessage & { content: string; contentParts?: MessagePart[] }>;
  report: Record<string, unknown>;
  vault: Record<string, string>;
}

export interface ReviewResult {
  allowed: boolean;
  severity: RiskLevel;
  findings: Array<Record<string, unknown>>;
  report: Record<string, unknown>;
  [key: string]: unknown;
}

export interface JsonProtectionResult extends Record<string, unknown> {
  allowed: boolean;
  blocked: boolean;
  json?: {
    parsed: unknown;
    schemaValid: boolean;
    parseError?: string;
  };
}

export interface ProviderAdapter {
  provider: string;
  invoke(payload: { messages: ShieldMessage[]; metadata?: Record<string, unknown>; guard?: GuardResult }): Promise<unknown> | unknown;
  extractOutput?(response: unknown, request?: GuardResult): unknown;
}

export interface ShieldOptions {
  preset?: string | null;
  policyPack?: string | null;
  shadowMode?: boolean;
  routePolicies?: Array<{ route: string | RegExp | ((route: string, metadata: Record<string, unknown>) => boolean); options: Record<string, unknown> }>;
  customPromptDetectors?: Array<(payload: Record<string, unknown>) => Record<string, unknown> | Array<Record<string, unknown>> | null>;
  onTelemetry?: (event: Record<string, unknown>) => void | Promise<void>;
  telemetryExporters?: Array<{ send(events: Array<Record<string, unknown>>): unknown }>;
  identityResolver?: (metadata: Record<string, unknown>) => Record<string, unknown> | null;
  [key: string]: unknown;
}

export class BlackwallShield {
  constructor(options?: ShieldOptions);
  inspectText(text: unknown): Record<string, unknown>;
  guardModelRequest(input?: { messages?: ShieldMessage[]; metadata?: Record<string, unknown>; allowSystemMessages?: boolean; comparePolicyPacks?: string[] }): Promise<GuardResult>;
  reviewModelResponse(input?: { output: unknown; metadata?: Record<string, unknown>; outputFirewall?: OutputFirewall | null; firewallOptions?: Record<string, unknown> }): Promise<ReviewResult>;
  protectModelCall(input: Record<string, unknown>): Promise<Record<string, unknown>>;
  protectJsonModelCall(input: Record<string, unknown>): Promise<JsonProtectionResult>;
  protectWithAdapter(input: { adapter: ProviderAdapter; messages?: ShieldMessage[]; metadata?: Record<string, unknown>; allowSystemMessages?: boolean; comparePolicyPacks?: string[]; outputFirewall?: OutputFirewall | null; firewallOptions?: Record<string, unknown> }): Promise<Record<string, unknown>>;
}

export class OutputFirewall {
  constructor(options?: Record<string, unknown>);
  inspect(output: unknown, options?: Record<string, unknown>): ReviewResult;
}

export class ToolPermissionFirewall {
  constructor(options?: Record<string, unknown>);
  inspectCall(input: Record<string, unknown>): Record<string, unknown>;
  inspectCallAsync?(input: Record<string, unknown>): Promise<Record<string, unknown>>;
}

export class ValueAtRiskCircuitBreaker {
  constructor(options?: Record<string, unknown>);
  inspect(input?: Record<string, unknown>): Record<string, unknown>;
  revokeSession(sessionId: string, durationMs?: number): Record<string, unknown> | null;
}

export class ShadowConsensusAuditor {
  constructor(options?: Record<string, unknown>);
  inspect(input?: Record<string, unknown>): Record<string, unknown>;
}

export class CrossModelConsensusWrapper {
  constructor(options?: Record<string, unknown>);
  evaluate(input?: Record<string, unknown>): Promise<Record<string, unknown>> | Record<string, unknown>;
}

export class DigitalTwinOrchestrator {
  constructor(options?: Record<string, unknown>);
  generate(): Record<string, unknown>;
  static fromToolPermissionFirewall(firewall: unknown): DigitalTwinOrchestrator;
}

export class DataClassificationGate {
  constructor(options?: Record<string, unknown>);
  classify(input?: Record<string, unknown>): string;
  inspect(input?: Record<string, unknown>): Record<string, unknown>;
}

export class ProviderRoutingPolicy {
  constructor(options?: Record<string, unknown>);
  choose(input?: Record<string, unknown>): Record<string, unknown>;
}

export class ApprovalInboxModel {
  constructor(options?: Record<string, unknown>);
  createRequest(input?: Record<string, unknown>): Record<string, unknown>;
  approve(id: string, approver: string): Record<string, unknown> | null;
  summarize(): Record<string, unknown>;
}

export class RetrievalTrustScorer {
  score(documents?: Array<Record<string, unknown>>): Array<Record<string, unknown>>;
}

export class OutboundCommunicationGuard {
  constructor(options?: Record<string, unknown>);
  inspect(input?: Record<string, unknown>): Record<string, unknown>;
}

export class UploadQuarantineWorkflow {
  constructor(options?: Record<string, unknown>);
  inspectUpload(input?: Record<string, unknown>): Promise<Record<string, unknown>>;
}

export class PolicyLearningLoop {
  constructor();
  recordDecision(input?: Record<string, unknown>): Record<string, unknown> | null;
  suggestOverrides(): Array<Record<string, unknown>>;
}

export class RetrievalSanitizer {
  constructor(options?: Record<string, unknown>);
  sanitizeDocuments(documents: Array<Record<string, unknown>>): Array<Record<string, unknown>>;
}

export class AuditTrail {
  constructor(options?: Record<string, unknown>);
  record(event?: Record<string, unknown>): Record<string, unknown>;
  summarize(): Record<string, unknown>;
}

export const SHIELD_PRESETS: Record<string, Record<string, unknown>>;
export const CORE_INTERFACES: Record<string, string>;
export const POLICY_PACKS: Record<string, Record<string, unknown>>;

export function buildShieldOptions(options?: Record<string, unknown>): Record<string, unknown>;
export function summarizeOperationalTelemetry(events?: Array<Record<string, unknown>>): Record<string, unknown>;
export function parseJsonOutput(output: unknown): unknown;
export function normalizeIdentityMetadata(metadata?: Record<string, unknown>, resolver?: ((metadata: Record<string, unknown>) => Record<string, unknown> | null) | null): Record<string, unknown>;
export function buildEnterpriseTelemetryEvent(event?: Record<string, unknown>, resolver?: ((metadata: Record<string, unknown>) => Record<string, unknown> | null) | null): Record<string, unknown>;
export function buildPowerBIRecord(event?: Record<string, unknown>): Record<string, unknown>;
export function buildComplianceEventBundle(event?: Record<string, unknown>): Record<string, unknown>;
export function sanitizeAuditEvent(event?: Record<string, unknown>, options?: Record<string, unknown>): Record<string, unknown>;
export function detectOperationalDrift(previousSummary?: Record<string, unknown>, currentSummary?: Record<string, unknown>): Record<string, unknown>;
export function suggestPolicyOverride(input?: Record<string, unknown>): Record<string, unknown> | null;
export class PowerBIExporter {
  constructor(options?: Record<string, unknown>);
  send(events?: Array<Record<string, unknown>> | Record<string, unknown>): Promise<Array<Record<string, unknown>>>;
}

export function createOpenAIAdapter(input: Record<string, unknown>): ProviderAdapter;
export function createAnthropicAdapter(input: Record<string, unknown>): ProviderAdapter;
export function createGeminiAdapter(input: Record<string, unknown>): ProviderAdapter;
export function createOpenRouterAdapter(input: Record<string, unknown>): ProviderAdapter;
