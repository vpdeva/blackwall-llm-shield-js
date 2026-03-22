# Next.js App Router Example

This example shows how to place Blackwall LLM Shield in front of every model request in a Next.js App Router route handler.

## Files

- `app/api/chat/route.js`
- `.env.example`

## Notes

- Keep the shield on the server only
- Import from `@vpdeva/blackwall-llm-shield-js`
- Mark trusted `system` prompts explicitly
- Send alerts to Slack, SIEM, PagerDuty, or an internal webhook
- Return a 403 when prompt-injection risk exceeds policy
- For streaming, apply request guarding before the provider call and apply output review to assembled/final content before returning it to the client
