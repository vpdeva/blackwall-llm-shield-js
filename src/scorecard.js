#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { BlackwallShield, runRedTeamSuite } = require('./index');

function parseScalar(value = '') {
  const trimmed = String(value).trim();
  if (trimmed === 'true') return true;
  if (trimmed === 'false') return false;
  if (/^-?\d+$/.test(trimmed)) return Number(trimmed);
  return trimmed.replace(/^['"]|['"]$/g, '');
}

function loadConfig(configPath) {
  const raw = fs.readFileSync(configPath, 'utf8');
  if (configPath.endsWith('.json')) return JSON.parse(raw);
  const result = {};
  let currentList = null;
  let currentItem = null;
  raw.split(/\r?\n/).forEach((line) => {
    if (!line.trim() || line.trim().startsWith('#')) return;
    if (/^[A-Za-z]/.test(line) && line.includes(':')) {
      const [key, rest] = line.split(/:\s*/, 2);
      if (!rest) {
        result[key.trim()] = [];
        currentList = result[key.trim()];
        currentItem = null;
      } else {
        result[key.trim()] = parseScalar(rest);
      }
      return;
    }
    const itemMatch = line.match(/^\s*-\s+([A-Za-z0-9_]+):\s*(.+)$/);
    if (itemMatch && currentList) {
      currentItem = { [itemMatch[1]]: parseScalar(itemMatch[2]) };
      currentList.push(currentItem);
      return;
    }
    const propMatch = line.match(/^\s+([A-Za-z0-9_]+):\s*(.+)$/);
    if (propMatch && currentItem) currentItem[propMatch[1]] = parseScalar(propMatch[2]);
  });
  return result;
}

async function main() {
  const args = process.argv.slice(2);
  const validateMode = args[0] === 'validate';
  const configIndex = args.indexOf('--config');
  const configPath = configIndex >= 0 ? path.resolve(args[configIndex + 1]) : null;
  const config = configPath ? loadConfig(configPath) : {};
  const shield = new BlackwallShield({
    blockOnPromptInjection: true,
    promptInjectionThreshold: process.env.BLACKWALL_PROMPT_THRESHOLD || 'high',
    shadowMode: process.env.BLACKWALL_SHADOW_MODE === 'true',
    ...config,
  });
  const scorecard = await runRedTeamSuite({ shield, metadata: { source: 'cli', mode: validateMode ? 'validate' : 'run' } });
  process.stdout.write(`${JSON.stringify(scorecard, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.message || String(error)}\n`);
  process.exit(1);
});
