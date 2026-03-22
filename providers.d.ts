export type { ProviderAdapter } from './index';

export function createOpenAIAdapter(input: Record<string, unknown>): import('./index').ProviderAdapter;
export function createAnthropicAdapter(input: Record<string, unknown>): import('./index').ProviderAdapter;
export function createGeminiAdapter(input: Record<string, unknown>): import('./index').ProviderAdapter;
export function createOpenRouterAdapter(input: Record<string, unknown>): import('./index').ProviderAdapter;
