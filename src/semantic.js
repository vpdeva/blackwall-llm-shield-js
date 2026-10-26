const { LightweightIntentScorer } = require('./index');

class TransformersIntentScorer {
  constructor(classifier, options = {}) {
    this.classifier = classifier;
    this.threshold = options.threshold || 0.5;
    this.labelMap = options.labelMap || {
      jailbreak: 'jailbreak',
      prompt_injection: 'prompt_injection',
      unsafe: 'unsafe',
      injection: 'prompt_injection',
      malicious: 'unsafe',
    };
  }

  async score(text) {
    const predictions = await this.classifier(String(text || ''));
    const items = Array.isArray(predictions) ? predictions : [predictions];
    const matches = [];
    let total = 0;
    for (const item of items) {
      const rawLabel = String(item.label || '').toLowerCase();
      const label = this.labelMap[rawLabel] || rawLabel;
      const score = Number(item.score || 0);
      if (['jailbreak', 'prompt_injection', 'unsafe'].includes(label) && score >= this.threshold) {
        const weighted = Math.min(40, Math.round(score * 40));
        total += weighted;
        matches.push({
          id: `transformers_${label}`,
          score: weighted,
          reason: `Local semantic model flagged ${label} intent`,
          probability: Number(score.toFixed(3)),
        });
      }
    }
    return { score: Math.min(total, 40), matches };
  }
}

async function createOptionalLocalIntentScorer(options = {}) {
  try {
    const { pipeline } = require('@xenova/transformers');
    const classifier = await pipeline('text-classification', options.model || 'ProtectAI/deberta-v3-base-prompt-injection-v2', options.revision ? { revision: options.revision } : undefined);
    return new TransformersIntentScorer(classifier, options);
  } catch (err) {
    // @xenova/transformers is an optional peer dependency; say once why semantic scoring fell back.
    if (!createOptionalLocalIntentScorer.warned && typeof process !== 'undefined' && process.emitWarning) {
      createOptionalLocalIntentScorer.warned = true;
      process.emitWarning(`Local semantic model unavailable (${err && err.code === 'MODULE_NOT_FOUND' ? 'install @xenova/transformers to enable it' : err && err.message}); using the lightweight intent scorer.`, 'BlackwallWarning');
    }
    return new LightweightIntentScorer(options);
  }
}

module.exports = {
  TransformersIntentScorer,
  createOptionalLocalIntentScorer,
};
