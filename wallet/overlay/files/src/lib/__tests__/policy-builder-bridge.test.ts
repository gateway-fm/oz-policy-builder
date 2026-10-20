// @vitest-environment node
import { webcrypto } from "node:crypto";
import { Buffer } from "buffer";
import base64url from "base64url";
import { expect, it, vi } from "vitest";
import { Account, Address, Keypair, Networks, Operation, StrKey, TransactionBuilder, hash, xdr } from "@stellar/stellar-sdk";
import type { Approval } from "../../policy-builder/shared/approval.mjs";
import { ownerRule, WEBAUTHN_WASM } from "../../policy-builder/shared/approval.mjs";
import type { CheckedAssembly } from "../../policy-builder/shared/assembly.mjs";
import { validateSignedAuthorization } from "../../policy-builder/shared/signature.mjs";

const webauthn = vi.hoisted(() => ({ authenticate: vi.fn() }));
vi.mock("@simplewebauthn/browser", () => ({ startAuthentication: webauthn.authenticate, startRegistration: vi.fn() }));
import { signWalletAuthEntries } from "../passkey";

function derSignature(raw: Uint8Array) {
  const integer = (value: Uint8Array) => {
    let data = Buffer.from(value);
    while (data.length > 1 && data[0] === 0) data = data.subarray(1);
    if (data[0] & 128) data = Buffer.concat([Buffer.from([0]), data]);
    return Buffer.concat([Buffer.from([2, data.length]), data]);
  };
  const body = Buffer.concat([integer(raw.subarray(0, 32)), integer(raw.subarray(32))]);
  return Buffer.concat([Buffer.from([48, body.length]), body]);
}

it("validates an actual SDK16 Pollywallet passkey signature in the isolated SDK17 validator", async () => {
  vi.stubGlobal("crypto", webcrypto);
  try {
    const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const publicKey = Buffer.from(await crypto.subtle.exportKey("raw", keys.publicKey)).toString("hex");
    const account = StrKey.encodeContract(Buffer.alloc(32, 12));
    const verifier = StrKey.encodeContract(Buffer.alloc(32, 13));
    const origin = "http://localhost:3000";
    const expiration = 200;
    const entry = new xdr.SorobanAuthorizationEntry({
      credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(new xdr.SorobanAddressCredentials({
        address: new Address(account).toScAddress(), nonce: xdr.Int64.fromString("42"),
        signatureExpirationLedger: expiration, signature: xdr.ScVal.scvVoid(),
      })),
      rootInvocation: new xdr.SorobanAuthorizedInvocation({
        function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
          new xdr.InvokeContractArgs({ contractAddress: new Address(account).toScAddress(), functionName: "add_context_rule", args: [] })),
        subInvocations: [],
      }),
    });
    const payer = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 8));
    const transaction = new TransactionBuilder(new Account(payer.publicKey(), "0"), { fee: "100", networkPassphrase: Networks.TESTNET })
      .addOperation(Operation.invokeHostFunction({ func: xdr.HostFunction.hostFunctionTypeInvokeContract(entry.rootInvocation().function().contractFn()), auth: [entry] }))
      .setTimeout(0).build();
    const approval: Approval = { wallet: { contractId: account, verifier, credentialId: "AQ", publicKey },
      ownerRuleId: 7, ownerRuleXdr: "unused", commitment: "a".repeat(64), observedLedger: 100,
      intent: {}, expected: {}, authorities: [], approval_state: "reviewed_not_signed", trust_basis: "wallet_owned_passkey_identity" };
    const fields = {
      context_type: xdr.ScVal.scvVec([xdr.ScVal.scvSymbol("Default")]),
      id: xdr.ScVal.scvU32(7), policies: xdr.ScVal.scvVec([]),
      signers: xdr.ScVal.scvVec([xdr.ScVal.scvVec([xdr.ScVal.scvSymbol("External"), new Address(verifier).toScVal(),
        xdr.ScVal.scvBytes(Buffer.concat([Buffer.from(publicKey, "hex"), Buffer.from([1])]))])]),
      valid_until: xdr.ScVal.scvVoid(),
    };
    const ruleXdr = xdr.ScVal.scvMap(Object.entries(fields).map(([name, val]) =>
      new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(name), val }))).toXDR("base64");
    expect(ownerRule({ authority: { verdict: { observed_ledger: 100, authority_list: [{
      rule_id: 7, reach: { kind: "any_call" }, valid_until: null, requirement: { kind: "all_of", signers: [{
        kind: "external", scheme: "webauthn_p256", public_key: publicKey, verifier, verifier_code_hash: WEBAUTHN_WASM,
        aliases_restricted_key: false,
      }] },
    }] } } }, approval.wallet, ruleXdr)).toBe(7);
    const checked: CheckedAssembly = { envelopeXdr: transaction.toXDR(), authEntriesXdr: [entry.toXDR("base64")],
      ownerRuleId: 7, expirationLedger: expiration, authorityCommitment: approval.commitment,
      minLedger: 100, maxLedger: 201, feeStroops: 100 };
    webauthn.authenticate.mockImplementation(async ({ optionsJSON }: { optionsJSON: { challenge: string } }) => {
      const client = Buffer.from(JSON.stringify({ type: "webauthn.get", origin, challenge: optionsJSON.challenge, crossOrigin: false }));
      const auth = Buffer.concat([hash(Buffer.from("localhost")), Buffer.from([5, 0, 0, 0, 0])]);
      const signedBytes = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keys.privateKey,
        new Uint8Array(Buffer.concat([auth, hash(client)])));
      return { response: { authenticatorData: base64url(auth), clientDataJSON: base64url(client),
        signature: base64url(derSignature(new Uint8Array(signedBytes))) } };
    });
    const signed = await signWalletAuthEntries({ authEntries: [entry], wallet: approval.wallet,
      contextRuleIds: [7], expiration, verifier });
    const result = await validateSignedAuthorization({ approval, checked,
      signedAuthEntriesXdr: signed.map((value) => value.toXDR("base64")), origin });
    expect(result.authentication).toBe("webauthn_user_verified");
    expect(result.human_approval_attested).toBe(false);
    expect(webauthn.authenticate).toHaveBeenCalledTimes(1);
    await expect(validateSignedAuthorization({ approval: { ...approval, ownerRuleId: 0 }, checked,
      signedAuthEntriesXdr: signed.map((value) => value.toXDR("base64")), origin })).rejects.toThrow("wallet signature refused");
  } finally {
    vi.unstubAllGlobals();
    webauthn.authenticate.mockReset();
  }
});
