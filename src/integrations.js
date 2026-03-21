const {
  createExpressMiddleware,
  createLangChainCallbacks,
  createLlamaIndexCallback,
} = require('./index');

class BlackwallLangChainCallback {
  constructor(options = {}) {
    this.options = options;
    this.handlers = createLangChainCallbacks(options);
    this.lastResult = null;
    this.outputFirewall = options.outputFirewall || null;
    this.lastOutputReview = null;
  }

  async handleLLMStart(llm, prompts = []) {
    const results = await this.handlers.handleLLMStart(llm, prompts);
    this.lastResult = results[results.length - 1] || null;
    if (results.some((item) => item && item.allowed === false)) {
      throw new Error(this.lastResult && this.lastResult.reason ? this.lastResult.reason : 'Blackwall blocked prompt');
    }
    return results;
  }

  async guardMessages(messages, metadata = {}) {
    const result = await this.handlers.guardMessages(messages, metadata);
    this.lastResult = result;
    if (result && result.allowed === false) throw new Error(result.reason || 'Blackwall blocked prompt');
    return result;
  }

  async handleLLMEnd(output) {
    if (!this.outputFirewall || typeof this.outputFirewall.inspect !== 'function') return null;
    const generations = output && output.generations ? output.generations : [];
    const text = Array.isArray(generations) && generations[0] && generations[0][0]
      ? (generations[0][0].text || generations[0][0].message?.content || '')
      : '';
    const review = this.outputFirewall.inspect(text);
    this.lastOutputReview = review;
    if (review && review.allowed === false) throw new Error('Blackwall blocked model output');
    return review;
  }
}

class BlackwallLlamaIndexCallback {
  constructor(options = {}) {
    this.options = options;
    this.handler = createLlamaIndexCallback(options);
    this.lastResult = null;
    this.outputFirewall = options.outputFirewall || null;
    this.lastOutputReview = null;
  }

  async onEventStart(event) {
    const result = await this.handler.onEventStart(event);
    this.lastResult = result;
    if (result && result.allowed === false) throw new Error(result.reason || 'Blackwall blocked prompt');
    return result;
  }

  async onEventEnd(event) {
    if (!this.outputFirewall || typeof this.outputFirewall.inspect !== 'function') return null;
    const payload = event && event.payload ? event.payload : {};
    const text = payload.response || payload.output || '';
    const review = this.outputFirewall.inspect(text);
    this.lastOutputReview = review;
    if (review && review.allowed === false) throw new Error('Blackwall blocked model output');
    return review;
  }
}

module.exports = {
  BlackwallLangChainCallback,
  BlackwallLlamaIndexCallback,
  createExpressMiddleware,
  createLangChainCallbacks,
  createLlamaIndexCallback,
};
