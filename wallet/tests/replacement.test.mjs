import assert from 'node:assert/strict';
import test from 'node:test';
import { StrKey } from '@stellar/stellar-sdk';
import { replacementConsent } from '../shared/replacement.mjs';
const fixture = () => ({ installation: { account: StrKey.encodeContract(Buffer.alloc(32, 1)),
  installationId: '1'.repeat(64), transactionHash: '2'.repeat(64), ruleId: 8 },
removal: { status: 'removed', ruleId: 8, transactionHash: '3'.repeat(64), event: 'verified', ruleReadback: 'absent' } });
test('replacement acknowledgement names the removed grant and discloses additive historical authority', () => {
  const display = replacementConsent(fixture());
  assert.equal(display.previousRuleId, 8); assert.equal(display.budget, 'previously_used_authority_plus_new_cap');
  assert.match(display.warning, /additional to the new grant/); assert.ok(Object.isFrozen(display));
});
for (const [name, change] of [
  ['unverified removal', (f) => { f.removal.status = 'confirmed_unverified'; }],
  ['present rule', (f) => { f.removal.ruleReadback = 'present'; }],
  ['wrong removed rule', (f) => { f.removal.ruleId++; }],
  ['unverified event', (f) => { f.removal.event = 'unverified'; }],
  ['missing removal transaction', (f) => { delete f.removal.transactionHash; }],
  ['owner rule', (f) => { f.installation.ruleId = 0; }],
  ['malformed account', (f) => { f.installation.account = 'different'; }],
]) test(`replacement consent refuses ${name}`, () => {
  const f = fixture(); change(f); assert.throws(() => replacementConsent(f), /refused/);
});
