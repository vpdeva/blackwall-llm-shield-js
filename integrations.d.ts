export { BlackwallShield, OutputFirewall, type ProviderAdapter } from './index';

export class BlackwallLangChainCallback {
  constructor(options?: Record<string, unknown>);
  handleLLMStart(llm: unknown, prompts?: string[]): Promise<unknown>;
  guardMessages(messages: unknown, metadata?: Record<string, unknown>): Promise<unknown>;
  handleLLMEnd(output: unknown): Promise<unknown>;
}

export class BlackwallLlamaIndexCallback {
  constructor(options?: Record<string, unknown>);
  onEventStart(event: unknown): Promise<unknown>;
  onEventEnd(event: unknown): Promise<unknown>;
}

export function createExpressMiddleware(options?: Record<string, unknown>): (req: unknown, res: unknown, next: () => void) => Promise<void>;
export function createLangChainCallbacks(options?: Record<string, unknown>): Record<string, unknown>;
export function createLlamaIndexCallback(options?: Record<string, unknown>): Record<string, unknown>;
