# Next.js App Router Example

This example shows how to place Blackwall LLM Shield in front of every model request in a Next.js API route.

## Files

- `app/api/chat/route.js`
- `.env.example`

## Notes

- Keep the shield on the server only
- Mark trusted `system` prompts explicitly
- Send alerts to Slack, SIEM, PagerDuty, or an internal webhook
- Return a 403 when prompt-injection risk exceeds policy

