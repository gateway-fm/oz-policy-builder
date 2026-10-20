// @vitest-environment node
import { webcrypto } from "node:crypto";
import { Buffer } from "buffer";
import base64url from "base64url";
import { expect, it, vi } from "vitest";
import { Account, Address, Asset, Keypair, Networks, Operation, SorobanDataBuilder, StrKey, TransactionBuilder, hash, nativeToScVal, xdr } from "@stellar/stellar-sdk";
import type { Approval } from "../../policy-builder/shared/approval.mjs";
import { NETWORK_ID, ownerRule, WEBAUTHN_WASM } from "../../policy-builder/shared/approval.mjs";
import type { CheckedAssembly } from "../../policy-builder/shared/assembly.mjs";
import { validateSignedAuthorization } from "../../policy-builder/shared/signature.mjs";
import { reviewSample, validateSampleAssembly } from "../../policy-builder/shared/sample.mjs";

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

it.each(["install", "sample"] as const)("validates an actual SDK16 Pollywallet %s signature in the isolated SDK17 validator", async (kind) => {
  vi.stubGlobal("crypto", webcrypto);
  try {
    const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const publicKey = Buffer.from(await crypto.subtle.exportKey("raw", keys.publicKey)).toString("hex");
    const account = StrKey.encodeContract(Buffer.alloc(32, 12));
    const verifier = StrKey.encodeContract(Buffer.alloc(32, 13));
    const origin = "http://localhost:3000";
    const expiration = kind === "sample" ? 219 : 200;
    const ownerRuleId = kind === "sample" ? 0 : 7;
    const payer = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 8));
    const call = kind === "sample"
      ? new xdr.InvokeContractArgs({ contractAddress: new Address(Asset.native().contractId(Networks.TESTNET)).toScAddress(),
        functionName: "transfer", args: [new Address(account).toScVal(), new Address(payer.publicKey()).toScVal(),
          nativeToScVal(1_000_000n, { type: "i128" })] })
      : new xdr.InvokeContractArgs({ contractAddress: new Address(account).toScAddress(), functionName: "add_context_rule", args: [] });
    const entry = new xdr.SorobanAuthorizationEntry({
      credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(new xdr.SorobanAddressCredentials({
        address: new Address(account).toScAddress(), nonce: xdr.Int64.fromString("42"),
        signatureExpirationLedger: expiration, signature: xdr.ScVal.scvVoid(),
      })),
      rootInvocation: new xdr.SorobanAuthorizedInvocation({
        function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(call),
        subInvocations: [],
      }),
    });
    const transaction = new TransactionBuilder(new Account(payer.publicKey(), "100"), { fee: "1000", networkPassphrase: Networks.TESTNET })
      .addOperation(Operation.invokeHostFunction({ func: xdr.HostFunction.hostFunctionTypeInvokeContract(entry.rootInvocation().function().contractFn()), auth: [entry] }))
      .setLedgerbounds(100, 220).setTimeout(0)
      .setSorobanData(new SorobanDataBuilder().setResourceFee("100").build()).build();
    const approval: Approval = { wallet: { contractId: account, verifier, credentialId: "AQ", publicKey },
      ownerRuleId, ownerRuleXdr: "unused", commitment: "a".repeat(64), observedLedger: 100,
      intent: {}, expected: {}, authorities: [], approval_state: "reviewed_not_signed", trust_basis: "wallet_owned_passkey_identity" };
    const fields = {
      context_type: xdr.ScVal.scvVec([xdr.ScVal.scvSymbol("Default")]),
      id: xdr.ScVal.scvU32(ownerRuleId), name: xdr.ScVal.scvString("owner"), policies: xdr.ScVal.scvVec([]),
      signers: xdr.ScVal.scvVec([xdr.ScVal.scvVec([xdr.ScVal.scvSymbol("External"), new Address(verifier).toScVal(),
        xdr.ScVal.scvBytes(Buffer.concat([Buffer.from(publicKey, "hex"), Buffer.from([1])]))])]),
      valid_until: xdr.ScVal.scvVoid(),
    };
    const ruleXdr = xdr.ScVal.scvMap(Object.entries(fields).map(([name, val]) =>
      new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(name), val }))).toXDR("base64");
    expect(ownerRule({ authority: { verdict: { observed_ledger: 100, authority_list: [{
      rule_id: ownerRuleId, reach: { kind: "any_call" }, valid_until: null, requirement: { kind: "all_of", signers: [{
        kind: "external", scheme: "webauthn_p256", public_key: publicKey, verifier, verifier_code_hash: WEBAUTHN_WASM,
        aliases_restricted_key: false,
      }] },
    }] } } }, approval.wallet, ruleXdr)).toBe(ownerRuleId);
    const signingApproval = kind === "sample" ? reviewSample({ wallet: approval.wallet,
      descriptor: { recipient: payer.publicKey(), amountStroops: "1000000", ownerRuleXdr: ruleXdr },
      ownerRuleXdr: ruleXdr }) : approval;
    const checked: CheckedAssembly = kind === "sample" ? validateSampleAssembly({ approval: signingApproval,
      ownerRuleXdr: ruleXdr, assembly: {
        envelope_xdr_base64: transaction.toXDR(), envelope_xdr_sha256: hash(transaction.toEnvelope().toXDR()).toString("hex"),
        network_id: NETWORK_ID, fee_payer: payer.publicKey(), source_sequence: "100", fee_stroops: 1100,
        sequence_read_ledger: 100, simulation_ledger: 101, min_ledger: 100, max_ledger: 220, restoration: "none",
        simulation_auth_mode: "record", evidence_trust: "rpc_reported", state_dependent: true, writes_committed: false,
      }, limits: { feePayer: payer.publicKey(), sourceSequence: "100", maxFeeStroops: 10_000_000,
        currentLedger: 101, validityLedgers: 120, ownerReadLedger: 100 } })
      : { envelopeXdr: transaction.toXDR(), authEntriesXdr: [entry.toXDR("base64")],
        ownerRuleId, expirationLedger: expiration, authorityCommitment: approval.commitment,
        minLedger: 100, maxLedger: 220, feeStroops: 1100 };
    webauthn.authenticate.mockImplementation(async ({ optionsJSON }: { optionsJSON: { challenge: string } }) => {
      const client = Buffer.from(JSON.stringify({ type: "webauthn.get", origin, challenge: optionsJSON.challenge, crossOrigin: false }));
      const auth = Buffer.concat([hash(Buffer.from("localhost")), Buffer.from([5, 0, 0, 0, 0])]);
      const signedBytes = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keys.privateKey,
        new Uint8Array(Buffer.concat([auth, hash(client)])));
      return { response: { authenticatorData: base64url(auth), clientDataJSON: base64url(client),
        signature: base64url(derSignature(new Uint8Array(signedBytes))) } };
    });
    const signed = await signWalletAuthEntries({ authEntries: [entry], wallet: approval.wallet,
      contextRuleIds: [ownerRuleId], expiration, verifier });
    const result = await validateSignedAuthorization({ approval: signingApproval, checked,
      signedAuthEntriesXdr: signed.map((value) => value.toXDR("base64")), origin });
    expect(result.authentication).toBe("webauthn_user_verified");
    expect(result.human_approval_attested).toBe(false);
    expect(webauthn.authenticate).toHaveBeenCalledTimes(1);
    await expect(validateSignedAuthorization({ approval: { ...signingApproval, ownerRuleId: ownerRuleId + 1 }, checked,
      signedAuthEntriesXdr: signed.map((value) => value.toXDR("base64")), origin })).rejects.toThrow("wallet signature refused");
  } finally {
    vi.unstubAllGlobals();
    webauthn.authenticate.mockReset();
  }
});
