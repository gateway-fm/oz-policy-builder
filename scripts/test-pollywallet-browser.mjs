// Run against the applied checkout's local Vite server. No transaction is submitted.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFileSync, realpathSync, unlinkSync, writeFileSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { chromium } from '../testnet-harness/browser/node_modules/playwright/index.mjs';

const checkout = process.argv[2];
if (process.argv.length !== 3 || !isAbsolute(checkout) || realpathSync(checkout) !== checkout) {
  throw new Error('Usage: node scripts/test-pollywallet-browser.mjs /absolute/applied/pollywallet');
}
const nested = JSON.parse(readFileSync(join(checkout, 'src/policy-builder/package.json')));
assert.equal(nested.dependencies['@stellar/stellar-sdk'], '17.2.1');
const channel = process.env.OZPB_BROWSER_CHANNEL;
if (channel !== undefined && !['chrome', 'chromium'].includes(channel)) throw new Error('Unsupported browser channel');
const name = `ozpb-browser-check-${randomBytes(8).toString('hex')}.mjs`;
const path = join(checkout, 'src/lib', name);
writeFileSync(path, `
import { Buffer } from 'buffer';
import { Account, Address, Keypair, Networks, Operation, StrKey, TransactionBuilder, xdr } from '@stellar/stellar-sdk';
import { createPasskey, signWalletAuthEntries } from './passkey';
import { validateSignedAuthorization } from '../policy-builder/shared/signature.mjs';
export async function check() {
  const credential = await createPasskey('Policy Builder test', 'Automated virtual authenticator');
  const wallet = { contractId: StrKey.encodeContract(Buffer.alloc(32, 12)),
    verifier: StrKey.encodeContract(Buffer.alloc(32, 13)), credentialId: credential.credentialId,
    publicKey: Buffer.from(credential.publicKey).toString('hex') };
  const entry = new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(new xdr.SorobanAddressCredentials({
      address: new Address(wallet.contractId).toScAddress(), nonce: xdr.Int64.fromString('42'),
      signatureExpirationLedger: 200, signature: xdr.ScVal.scvVoid(),
    })),
    rootInvocation: new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(new xdr.InvokeContractArgs({
        contractAddress: new Address(wallet.contractId).toScAddress(), functionName: 'add_context_rule', args: [],
      })), subInvocations: [],
    }),
  });
  const payer = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 8));
  const tx = new TransactionBuilder(new Account(payer.publicKey(), '0'), { fee: '100', networkPassphrase: Networks.TESTNET })
    .addOperation(Operation.invokeHostFunction({
      func: xdr.HostFunction.hostFunctionTypeInvokeContract(entry.rootInvocation().function().contractFn()), auth: [entry],
    })).setTimeout(0).build();
  const approval = { wallet, ownerRuleId: 7, commitment: 'a'.repeat(64) };
  const checked = { envelopeXdr: tx.toXDR(), authEntriesXdr: [entry.toXDR('base64')],
    ownerRuleId: 7, expirationLedger: 200, authorityCommitment: approval.commitment,
    minLedger: 100, maxLedger: 201, feeStroops: 100 };
  const signed = await signWalletAuthEntries({ authEntries: [entry], wallet,
    contextRuleIds: [7], expiration: 200, verifier: wallet.verifier });
  const result = await validateSignedAuthorization({ approval, checked,
    signedAuthEntriesXdr: signed.map((value) => value.toXDR('base64')), origin: window.location.origin });
  return { origin: window.location.origin, authentication: result.authentication,
    human_approval_attested: result.human_approval_attested };
}
`, { flag: 'wx', mode: 0o600 });
let browser;
try {
  browser = await chromium.launch({ headless: true, ...(channel ? { channel } : {}) });
  const page = await browser.newPage();
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal',
    hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  await page.goto('http://localhost:3000/policy-builder');
  await page.waitForLoadState('networkidle');
  const result = await page.evaluate(async (modulePath) => (await import(modulePath)).check(), `/src/lib/${name}`);
  assert.equal(result.origin, 'http://localhost:3000');
  assert.equal(result.authentication, 'webauthn_user_verified');
  assert.equal(result.human_approval_attested, false);
  console.log('Actual Pollywallet registration and UV assertion passed through the SDK16→SDK17 browser bridge. No transaction submitted; human approval not attested.');
} finally {
  await browser?.close();
  unlinkSync(path);
}
