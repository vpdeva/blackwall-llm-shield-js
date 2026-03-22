function stringifyContent(content) {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    return content.map((item) => {
      if (typeof item === 'string') return item;
      if (item && typeof item.text === 'string') return item.text;
      if (item && item.type === 'text' && typeof item.text === 'string') return item.text;
      return '';
    }).filter(Boolean).join('\n');
  }
  if (content && typeof content.text === 'string') return content.text;
  return String(content || '');
}

function toOpenAIInput(messages = []) {
  return messages.map((message) => ({
    role: message.role,
    content: stringifyContent(message.content),
  }));
}

function toAnthropicMessages(messages = []) {
  return messages
    .filter((message) => message.role !== 'system')
    .map((message) => ({
      role: message.role === 'assistant' ? 'assistant' : 'user',
      content: stringifyContent(message.content),
    }));
}

function extractSystemPrompt(messages = []) {
  return messages.filter((message) => message.role === 'system').map((message) => stringifyContent(message.content)).join('\n\n');
}

function defaultAdapterResult(response, output) {
  return { response, output };
}

function createOpenAIAdapter({ client, model, request = {}, method = 'responses', extractOutput = null } = {}) {
  if (!client) throw new TypeError('client is required');
  return {
    provider: 'openai',
    async invoke({ messages, metadata = {} }) {
      if (method === 'chat.completions') {
        const response = await client.chat.completions.create({
          model,
          messages: toOpenAIInput(messages),
          metadata,
          ...request,
        });
        return defaultAdapterResult(response, response && response.choices && response.choices[0] && response.choices[0].message
          ? stringifyContent(response.choices[0].message.content)
          : '');
      }
      const response = await client.responses.create({
        model,
        input: toOpenAIInput(messages),
        metadata,
        ...request,
      });
      return defaultAdapterResult(response, response && typeof response.output_text === 'string' ? response.output_text : '');
    },
    extractOutput(response) {
      if (typeof extractOutput === 'function') return extractOutput(response);
      if (response && typeof response.output_text === 'string') return response.output_text;
      return response && response.choices && response.choices[0] && response.choices[0].message
        ? stringifyContent(response.choices[0].message.content)
        : '';
    },
  };
}

function createAnthropicAdapter({ client, model, request = {}, extractOutput = null } = {}) {
  if (!client) throw new TypeError('client is required');
  return {
    provider: 'anthropic',
    async invoke({ messages, metadata = {} }) {
      const response = await client.messages.create({
        model,
        system: extractSystemPrompt(messages) || undefined,
        messages: toAnthropicMessages(messages),
        metadata,
        ...request,
      });
      const output = Array.isArray(response && response.content)
        ? response.content.map((item) => stringifyContent(item)).filter(Boolean).join('\n')
        : '';
      return defaultAdapterResult(response, output);
    },
    extractOutput(response) {
      if (typeof extractOutput === 'function') return extractOutput(response);
      return Array.isArray(response && response.content)
        ? response.content.map((item) => stringifyContent(item)).filter(Boolean).join('\n')
        : '';
    },
  };
}

function createGeminiAdapter({ client, model, request = {}, extractOutput = null } = {}) {
  if (!client) throw new TypeError('client is required');
  return {
    provider: 'gemini',
    async invoke({ messages }) {
      const response = await client.models.generateContent({
        model,
        contents: messages.map((message) => ({
          role: message.role === 'assistant' ? 'model' : 'user',
          parts: [{ text: stringifyContent(message.content) }],
        })),
        ...request,
      });
      return defaultAdapterResult(response, response && typeof response.text === 'string' ? response.text : '');
    },
    extractOutput(response) {
      if (typeof extractOutput === 'function') return extractOutput(response);
      if (response && typeof response.text === 'string') return response.text;
      if (typeof response === 'string') return response;
      return '';
    },
  };
}

function createOpenRouterAdapter({ client, model, request = {}, extractOutput = null } = {}) {
  if (!client) throw new TypeError('client is required');
  return {
    provider: 'openrouter',
    async invoke({ messages }) {
      const response = await client.chat.completions.create({
        model,
        messages: toOpenAIInput(messages),
        ...request,
      });
      const output = response && response.choices && response.choices[0] && response.choices[0].message
        ? stringifyContent(response.choices[0].message.content)
        : '';
      return defaultAdapterResult(response, output);
    },
    extractOutput(response) {
      if (typeof extractOutput === 'function') return extractOutput(response);
      return response && response.choices && response.choices[0] && response.choices[0].message
        ? stringifyContent(response.choices[0].message.content)
        : '';
    },
  };
}

module.exports = {
  createOpenAIAdapter,
  createAnthropicAdapter,
  createGeminiAdapter,
  createOpenRouterAdapter,
};
