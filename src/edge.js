const EDGE_PROMPT_PATTERNS = [
  { id: 'ignore_instructions', score: 25, regex: /\bignore\b.{0,40}\b(instructions?|policy|guardrails?|safety)\b/i },
  { id: 'secret_exfiltration', score: 25, regex: /\b(reveal|dump|print|show)\b.{0,40}\b(secret|token|system prompt|hidden instructions?)\b/i },
  { id: 'tool_override', score: 20, regex: /\b(bypass|override|disable)\b.{0,40}\b(tool|policy|guardrail|safety)\b/i },
];

function edgeRiskLevel(score) {
  if (score >= 70) return 'critical';
  if (score >= 45) return 'high';
  if (score >= 20) return 'medium';
  return 'low';
}

function detectPromptInjectionEdge(input = '') {
  const text = String(input || '');
  const matches = EDGE_PROMPT_PATTERNS.filter((rule) => rule.regex.test(text)).map((rule) => ({
    id: rule.id,
    score: rule.score,
    reason: `Edge rule matched ${rule.id}`,
  }));
  const score = Math.min(matches.reduce((sum, item) => sum + item.score, 0), 100);
  return {
    score,
    level: edgeRiskLevel(score),
    matches,
    blockedByDefault: score >= 45,
  };
}

function maskTextEdge(text = '') {
  let masked = String(text || '');
  const vault = {};
  const patterns = [
    ['EMAIL', /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g],
    ['CREDIT_CARD', /\b(?:\d{4}[\s-]?){3}\d{4}\b/g],
    ['API_KEY', /\b(?:sk|rk|pk|api)[-_][A-Za-z0-9_-]{8,}\b/g],
    ['JWT', /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+\b/g],
    ['BEARER', /\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b/gi],
    ['PHONE', /(\+?\d{1,3}[\s-]?)?(\(0\d\)|0\d|\(?\d{2,4}\)?)[\s-]?\d{3,4}[\s-]?\d{3,4}\b/g],
  ];
  for (const [label, pattern] of patterns) {
    masked = masked.replace(pattern, (match) => {
      const token = `[${label}_${Object.keys(vault).length + 1}]`;
      vault[token] = match;
      return token;
    });
  }
  return { masked, vault, hasSensitiveData: Object.keys(vault).length > 0 };
}

class EdgeBlackwallShield {
  async guardModelRequest({ messages = [], metadata = {} } = {}) {
    const text = (Array.isArray(messages) ? messages : []).map((item) => String(item.content || '')).join('\n');
    const masked = maskTextEdge(text);
    const injection = detectPromptInjectionEdge(text);
    return {
      allowed: !injection.blockedByDefault,
      blocked: injection.blockedByDefault,
      reason: injection.blockedByDefault ? 'Prompt injection risk exceeded edge threshold' : null,
      messages,
      report: { metadata, promptInjection: injection, sensitiveData: masked },
      vault: masked.vault,
    };
  }
}

module.exports = {
  EdgeBlackwallShield,
  detectPromptInjectionEdge,
  maskTextEdge,
};
