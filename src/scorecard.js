#!/usr/bin/env node

const { BlackwallShield, runRedTeamSuite } = require('./index');

async function main() {
  const shield = new BlackwallShield({
    blockOnPromptInjection: true,
    promptInjectionThreshold: process.env.BLACKWALL_PROMPT_THRESHOLD || 'high',
    shadowMode: process.env.BLACKWALL_SHADOW_MODE === 'true',
  });
  const scorecard = await runRedTeamSuite({ shield, metadata: { source: 'cli' } });
  process.stdout.write(`${JSON.stringify(scorecard, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.message || String(error)}\n`);
  process.exit(1);
});
