# Contributing

Thanks for contributing.

## Good First Issues

- Add more production-grade examples for Next.js App Router streaming and tool-calling routes
- Improve `StreamingOutputFirewall` regression coverage with partial-chunk leak cases
- Expand `shield.use(plugin)` example plugins for output scanning and telemetry enrichment
- Add more multilingual red-team prompts and mutation fixtures to strengthen corpus hardening
- Tighten docs around `generateCoverageReport()` and how to regenerate the checked-in OWASP badge
- Improve edge runtime examples and document the tradeoffs versus the full Node runtime

## Development

```bash
npm test
```

## Guidelines

- Keep changes focused
- Add or update tests for behavior changes
- Avoid breaking public APIs without documenting it
- Prefer small, readable security rules over opaque magic

## Pull Requests

Please include:

- what changed
- why it changed
- test coverage or manual verification
- any security tradeoffs
