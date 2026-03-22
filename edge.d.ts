export function detectPromptInjectionEdge(input?: string): Record<string, unknown>;
export function maskTextEdge(input?: string): Record<string, unknown>;
export class EdgeBlackwallShield {
  guardModelRequest(input?: Record<string, unknown>): Promise<Record<string, unknown>>;
}
