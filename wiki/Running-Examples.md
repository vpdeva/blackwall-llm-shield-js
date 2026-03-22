# Running Examples

This page is wiki-ready and can be copied directly into the GitHub Wiki for the JS package if you want the examples guide to live there permanently.

## Available Examples

- `examples/nextjs-app-router`
- `examples/admin-dashboard`

## Next.js App Router Example

Path: [`examples/nextjs-app-router`](/Users/vishnu/Documents/blackwall-llm-shield/blackwall-llm-shield-js/examples/nextjs-app-router)

This example shows how to put Blackwall in front of a Next.js App Router route handler.

### Run It

1. Install the package dependencies in your own Next.js app.
2. Copy the route example from [`app/api/chat/route.js`](/Users/vishnu/Documents/blackwall-llm-shield/blackwall-llm-shield-js/examples/nextjs-app-router/app/api/chat/route.js).
3. Copy environment values from [`.env.example`](/Users/vishnu/Documents/blackwall-llm-shield/blackwall-llm-shield-js/examples/nextjs-app-router/.env.example).
4. Start your Next.js app as usual:

```bash
npm install
npm run dev
```

### What It Demonstrates

- request guarding before the provider call
- route-level metadata and telemetry
- Gemini-compatible request wrapping
- server-only shielding in an App Router handler

### Notes

- Keep the shield on the server side only.
- Mark trusted `system` prompts explicitly.
- For streaming routes, guard the request first and review assembled/final output before returning it.

## Admin Dashboard Example

Path: [`examples/admin-dashboard`](/Users/vishnu/Documents/blackwall-llm-shield/blackwall-llm-shield-js/examples/admin-dashboard)

This example is a tiny static dashboard for visualizing event summaries.

### Run It

Open [`index.html`](/Users/vishnu/Documents/blackwall-llm-shield/blackwall-llm-shield-js/examples/admin-dashboard/index.html) in a browser, or serve the folder locally:

```bash
python3 -m http.server 8000
```

Then open `http://localhost:8000/examples/admin-dashboard/`.

### What It Demonstrates

- dashboard-friendly event rendering
- summary widgets for operators and security teams
- a simple presentation layer over `buildAdminDashboardModel(...)`

## Suggested Wiki Placement

If you want this to live in the GitHub Wiki instead of the repo tree, publish it as:

- `Running Examples`

and keep the in-repo copy as the source of truth for future edits.
