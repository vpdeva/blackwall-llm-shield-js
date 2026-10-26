const test = require('node:test');
const assert = require('node:assert/strict');
const {
  maskText, classifyIdentifiers, isValidNzIrd, isValidAuTfn, isValidAuMedicare, isValidAuAbn, isValidNzbn,
  AuditTrail, AgentIdentityRegistry,
} = require('../src/index.js');

test('NZ IRD checksum: published test numbers, bad checksums, out of range', () => {
  assert.ok(isValidNzIrd('49-091-850'));
  assert.ok(isValidNzIrd('136-410-132'));
  assert.ok(isValidNzIrd('49091850'));
  assert.ok(!isValidNzIrd('123-456-789'));
  assert.ok(!isValidNzIrd('9-999-999'));
  assert.ok(!isValidNzIrd('200-000-000'));
});

test('AU TFN, Medicare, ABN and NZBN checksums', () => {
  assert.ok(isValidAuTfn('123 456 782'));
  assert.ok(!isValidAuTfn('123 456 789'));
  assert.ok(isValidAuMedicare('2123 45670 1'));
  assert.ok(!isValidAuMedicare('2423 51673 1'));
  assert.ok(isValidAuAbn('51 824 753 556'));
  assert.ok(!isValidAuAbn('51 824 753 557'));
  assert.ok(!isValidAuAbn('10708502264'), 'no ABN can start with 10');
  assert.ok(isValidNzbn('9429051850012'));
  assert.ok(!isValidNzbn('9429051850013'));
});

test('IRD is masked as nzIrd, not phone', () => {
  const r = maskText('Employee IRD 49-091-850 starts Monday.');
  assert.ok(r.findings.some((f) => f.type === 'nzIrd'));
  assert.ok(!r.masked.includes('49-091-850'));
});

test('business numbers survive masking and are still classified', () => {
  const text = 'Example Services Ltd, NZBN 9429051850012, ABN 51 824 753 556.';
  const r = maskText(text);
  assert.ok(r.masked.includes('9429051850012'));
  assert.ok(r.masked.includes('51 824 753 556'));
  const kinds = new Set(classifyIdentifiers(text).map((x) => x.type));
  assert.ok(kinds.has('nzbn') && kinds.has('auAbn'));
});

test('tender wording is left alone, and an invalid TFN-shaped number is not labelled tfn', () => {
  const text = 'The Supplier must hold public liability insurance of not less than $10,000,000 for any one occurrence.';
  assert.equal(maskText(text).masked, text);
  assert.ok(!maskText('Reference 123 456 789 applies.').findings.some((f) => f.type === 'tfn'));
});

test('no shared default signing secret', () => {
  const a = new AuditTrail(); const b = new AuditTrail();
  const r1 = new AgentIdentityRegistry(); const r2 = new AgentIdentityRegistry();
  assert.notEqual(a.secret, b.secret);
  assert.notEqual(r1.secret, r2.secret);
  assert.ok(!a.secret.includes('blackwall'));
  assert.ok(a.secret.length >= 64);
});

test('environment secret is used when set', () => {
  process.env.BLACKWALL_AUDIT_SECRET = 'x'.repeat(40);
  try { assert.equal(new AuditTrail().secret, 'x'.repeat(40)); } finally { delete process.env.BLACKWALL_AUDIT_SECRET; }
});
