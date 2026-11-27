#!/usr/bin/env python3
"""Find and capture the mainnet transactions behind the recorder's fixture corpus.

Public RPC serves `getTransaction` only inside its retention window (about seven days on
mainnet), so a transaction worth keeping has to be captured while it is still served. This
script does both halves, read-only, against a public mainnet RPC:

  find [--rpc URL] [--start LEDGER ...] [--pages N]
      Scan `getTransactions` (decoded with `xdrFormat: json`) forward from each START, plus
      the transactions behind OpenZeppelin smart-account events (`getEvents`) across the
      retention window, and print, as JSON, one distinct transaction per corpus case found
      and the ledger windows scanned. Every referenced contract instance must still be live.
      Nothing is written.
  capture [--rpc URL] SELECTION.json
      For each case in SELECTION (the output of `find`, or the committed manifest, to refresh
      the same transactions while they are retained), store the verbatim `result` of every
      call the recorder's acquisition path makes for it: `getNetwork`, `getTransaction`
      (base64, as `ozpb_source_rpc::get_transaction` asks), and `getLedgerEntries` for the
      contract instances the transaction references. Then write the manifest. The corpus is
      replaced only once every case has been captured with every instance it references live
      in the answer, so a transaction that has left the endpoint's retention, or an instance
      that has since been archived, cannot leave a mix of old and new cases behind.

Without --rpc, Gateway's public mainnet RPC is used, and mainnet.sorobanrpc.com if it does
not answer.

Nothing is signed, simulated or submitted. Every value stored is public ledger data. Run with
`python3 -I`; it imports only the standard library.
"""
import argparse
import base64
import json
import shutil
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

PASSPHRASE = "Public Global Stellar Network ; September 2015"
DEFAULT_RPCS = ["https://rpc.mainnet.stellar.gateway.fm", "https://mainnet.sorobanrpc.com"]
ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "crates/source-rpc/tests/captured-mainnet"
USER_AGENT = "ozpb-fixture-capture/1"

# Case name -> what the fixture exercises. The order is the manifest's order.
CASES = {
    "sac-transfer-source-account": "Stellar Asset Contract transfer in a fee-bump envelope, authorized by the inner transaction source's source-account credential",
    "classic-address-credential": "invocation authorized by an address credential of an ed25519 (G) account that is not the transaction source",
    "smart-account-credential": "invocation authorized by the address credential of a smart account built on OpenZeppelin stellar-accounts, so its __check_auth ran",
    "nested-auth-tree": "authorization entry whose root invocation has sub-invocations, such as a swap reaching a token transfer",
    "fee-bump-invocation": "fee-bump envelope wrapping a Soroban invocation",
    "failed-invocation": "Soroban invocation that failed on-chain",
    "classic-multi-operation": "classic transaction with several operations and no InvokeHostFunction",
    "multi-authorizer": "invocation carrying authorization entries from several distinct addresses",
    "auth-args-divergence": "authorized root arguments differ from the invoked arguments of the same contract function",
    "credential-address-v2": "invocation authorized by the protocol-27 (CAP-71) AddressV2 credential arm",
    "credential-address-with-delegates": "invocation authorized by the protocol-27 (CAP-71) AddressWithDelegates credential arm",
}


def rpc(url, method, params=None):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})
    request = urllib.request.Request(
        url,
        data=body.encode(),
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
    )
    for attempt in range(4):
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                reply = json.loads(response.read())
            break
        except OSError as error:
            if attempt == 3:
                raise SystemExit(f"{method} at {url}: {error}")
            time.sleep(2 * (attempt + 1))
        except ValueError as error:
            raise SystemExit(f"{method} at {url}: the response is not JSON: {error}")
    if not isinstance(reply, dict) or "error" in reply or "result" not in reply:
        raise SystemExit(f"{method} at {url}: {reply.get('error', reply) if isinstance(reply, dict) else reply}")
    return reply["result"]


def endpoint(requested):
    """The RPC to use: the one asked for, or the first default that answers as mainnet."""
    for url in [requested] if requested else DEFAULT_RPCS:
        try:
            network = rpc(url, "getNetwork")
        except SystemExit as error:
            print(f"skipping {url}: {error}", file=sys.stderr)
            continue
        if network.get("passphrase") != PASSPHRASE:
            raise SystemExit(f"{url} is not mainnet: {network.get('passphrase')}")
        return url, network
    raise SystemExit("no mainnet RPC answered")


def strkey_payload(address):
    raw = base64.b32decode(address + "=" * (-len(address) % 8))
    return raw[1:33]


def account_identity(address):
    """Compare classic and muxed forms by their common Ed25519 key (SEP-23)."""
    if address.startswith(("G", "M")):
        return ("ed25519", strkey_payload(address))
    return ("other", address)


def instance_key(contract):
    """LedgerKey::ContractData for a contract's persistent instance entry, base64 XDR."""
    xdr = (
        (6).to_bytes(4, "big")  # CONTRACT_DATA
        + (1).to_bytes(4, "big")  # SC_ADDRESS_TYPE_CONTRACT
        + strkey_payload(contract)
        + (20).to_bytes(4, "big")  # SCV_LEDGER_KEY_CONTRACT_INSTANCE
        + (1).to_bytes(4, "big")  # PERSISTENT
    )
    return base64.b64encode(xdr).decode()


def arm(value):
    return value if isinstance(value, str) else next(iter(value))


def inner(envelope):
    kind, body = next(iter(envelope.items()))
    if kind == "tx_fee_bump":
        return kind, body["tx"]["inner_tx"]["tx"]["tx"]
    return kind, body["tx"]


def credential_address(credentials):
    if isinstance(credentials, str):
        return None
    value = next(iter(credentials.values()))
    return value.get("address") or value.get("address_credentials", {}).get("address")


def tree(invocation):
    yield invocation
    for child in invocation.get("sub_invocations", []):
        yield from tree(child)


def contract_fn(invocation):
    function = invocation["function"]
    return function.get("contract_fn") if isinstance(function, dict) else None


def referenced_contracts(envelope):
    """What `recorder_core::referenced_contract_addresses` returns for executed evidence."""
    _, tx = inner(envelope)
    found = set()
    for operation in tx["operations"]:
        body = operation["body"]
        if arm(body) != "invoke_host_function":
            continue
        invoke = body["invoke_host_function"]
        host = invoke["host_function"]
        if arm(host) == "invoke_contract":
            found.add(host["invoke_contract"]["contract_address"])
        for entry in invoke["auth"]:
            found.add(credential_address(entry["credentials"]))
            for node in tree(entry["root_invocation"]):
                call = contract_fn(node)
                if call:
                    found.add(call["contract_address"])
    return sorted(a for a in found if a and a.startswith("C"))


def cases_of(record):
    """Corpus cases this decoded transaction qualifies for, each with a penalty (0 = ideal)."""
    kind, tx = inner(record["envelopeJson"])
    success = record["status"] == "SUCCESS"
    operations = tx["operations"]
    invokes = [op for op in operations if arm(op["body"]) == "invoke_host_function"]
    found = {}
    if not invokes:
        if success and kind == "tx" and 2 <= len(operations) <= 4:
            found["classic-multi-operation"] = 0
        return found
    operation = invokes[0]
    invoke = operation["body"]["invoke_host_function"]
    source = operation.get("source_account") or tx["source_account"]
    host = invoke["host_function"]
    auth = invoke["auth"]
    call = host.get("invoke_contract") if isinstance(host, dict) else None
    arms = [arm(entry["credentials"]) for entry in auth]
    authorizers = [credential_address(entry["credentials"]) or source for entry in auth]
    identities = {account_identity(address) for address in authorizers}
    inner_source = account_identity(tx["source_account"])
    plain = 0 if kind == "tx" else 1  # a plain envelope keeps each case apart from the fee bump
    # A fee bump counts only when another account pays: both fee-bump cases' tests require it.
    payer = record["envelopeJson"]["tx_fee_bump"]["tx"]["fee_source"] if kind == "tx_fee_bump" else None
    payer_identity = account_identity(payer) if payer is not None else None
    paid_by_another = payer_identity is not None and payer_identity != inner_source
    if not success:
        if call:
            found["failed-invocation"] = plain
        return found
    if paid_by_another and payer_identity not in identities:
        # The relayer pattern: one party pays the fee, another authorizes the call.
        found["fee-bump-invocation"] = 0 if "address" in arms else 1
    if (paid_by_another and call and call["function_name"] == "transfer" and arms == ["source_account"]
            and identities == {inner_source}):
        # Fee-bumped only: the case pins that the credential resolves to the inner source and
        # never to the fee payer, and its test requires the fee bump.
        found["sac-transfer-source-account"] = 0
    if arms == ["address"] and authorizers[0].startswith("G") and identities != {inner_source}:
        found["classic-address-credential"] = plain
    if any(a.startswith("C") for a in authorizers):
        # Ideally the account authorizes a call into another contract, not its own management.
        roots = [contract_fn(entry["root_invocation"]) for entry in auth]
        external = any(r and r["contract_address"] not in authorizers for r in roots)
        found["smart-account-credential"] = (0 if external else 1) + (0 if len(auth) == 1 else 2)
    for entry in auth:
        if len(list(tree(entry["root_invocation"]))) >= 2:
            root = contract_fn(entry["root_invocation"])
            found["nested-auth-tree"] = 0 if root and "swap" in root["function_name"] else 1
            break
    if len(identities) >= 2:
        found["multi-authorizer"] = 0 if len(auth) <= 3 else 1
    for entry in auth:
        root = contract_fn(entry["root_invocation"])
        if call and root and (root["contract_address"], root["function_name"]) == (
            call["contract_address"],
            call["function_name"],
        ) and root["args"] != call["args"]:
            found["auth-args-divergence"] = 0
    for name in set(arms) - {"source_account", "address"}:
        found[f"credential-{name.replace('_', '-')}"] = 0
    return found


def instances(url, contracts):
    """Decoded contract instances by address, or None when any is absent."""
    if not contracts:
        return {}
    result = rpc(url, "getLedgerEntries", {"keys": [instance_key(c) for c in contracts], "xdrFormat": "json"})
    by_contract = {}
    for entry in result.get("entries", []):
        if entry.get("liveUntilLedgerSeq", 0) < result["latestLedger"]:
            continue  # archived: the acquisition refuses an instance that is not live
        data = entry["dataJson"]["contract_data"]
        by_contract[data["contract"]] = data["val"]["contract_instance"]["executable"]
    return by_contract if len(by_contract) == len(contracts) else None


def unusable_instances(keys, result):
    """Why a `getLedgerEntries` answer cannot stand in the corpus, or None. The recorder refuses
    a case unless every instance asked for is in the answer and live at its `latestLedger`."""
    answered = [entry.get("key") for entry in result.get("entries") or []]
    if len(set(answered)) != len(answered):
        return "an instance is answered more than once"
    if set(answered) - set(keys):
        return "the answer holds an unrequested key"
    entries = {entry.get("key"): entry for entry in result.get("entries") or []}
    for key in keys:
        if key not in entries:
            return "an instance is missing from the answer"
        if entries[key].get("liveUntilLedgerSeq", 0) < result["latestLedger"]:
            return "an instance is archived"
    return None


def is_oz_account(url, executable):
    """Whether a smart account's code is built on OpenZeppelin stellar-accounts: its storage
    layer emits `context_rule_added`, which wrappers keep even when they rename the methods."""
    if not isinstance(executable, dict) or "wasm" not in executable:
        return False
    key = base64.b64encode((7).to_bytes(4, "big") + bytes.fromhex(executable["wasm"])).decode()
    result = rpc(url, "getLedgerEntries", {"keys": [key], "xdrFormat": "base64"})
    if not result.get("entries"):
        return False
    return b"context_rule_added" in base64.b64decode(result["entries"][0]["xdr"])


def acceptable(url, case, record):
    """Every referenced instance must be live now, or the acquisition refuses the capture."""
    executables = instances(url, referenced_contracts(record["envelopeJson"]))
    if executables is None:
        return False
    invoke = inner(record["envelopeJson"])[1]["operations"][0]["body"].get("invoke_host_function", {})
    if case == "sac-transfer-source-account":
        return executables.get(invoke["host_function"]["invoke_contract"]["contract_address"]) == "stellar_asset"
    if case == "smart-account-credential":
        accounts = [credential_address(e["credentials"]) or "" for e in invoke["auth"]]
        return any(a.startswith("C") and is_oz_account(url, executables.get(a)) for a in accounts)
    return True


# OpenZeppelin stellar-accounts events: policies emit `*_enforced` from inside the account's
# `__check_auth`, and the account emits `signer_added` when a rule gains a signer. Transactions
# carrying them are where a mainnet OpenZeppelin account authorized something, which a sample
# of `getTransactions` pages rarely reaches.
OZ_EVENTS = ["spending_limit_enforced", "simple_enforced", "weighted_enforced", "signer_added"]


def symbol_topic(name):
    raw = name.encode()
    return base64.b64encode((15).to_bytes(4, "big") + len(raw).to_bytes(4, "big") + raw + b"\0" * (-len(raw) % 4)).decode()


def oz_transactions(url):
    """Transactions carrying OpenZeppelin account events, and the ledger window searched."""
    start = rpc(url, "getHealth")["oldestLedger"] + 100
    filters = [{"type": "contract", "topics": [[symbol_topic(n), "**"]]} for n in OZ_EVENTS]
    params = {"startLedger": start, "filters": filters, "pagination": {"limit": 1000}}
    hashes = []
    while True:
        page = rpc(url, "getEvents", params)
        hashes += [e["txHash"] for e in page["events"] if e["txHash"] not in hashes]
        if int(page["cursor"].split("-")[0]) >> 32 >= page["latestLedger"]:
            return hashes, [start, page["latestLedger"]]
        params = {"filters": filters, "pagination": {"cursor": page["cursor"], "limit": 1000}}


# Rare cases pick first, so a transaction that qualifies for several is spent on the rarest.
PICK_ORDER = [
    "smart-account-credential",
    "credential-address-with-delegates",
    "credential-address-v2",
    "auth-args-divergence",
    "sac-transfer-source-account",
    "failed-invocation",
    "classic-address-credential",
    "nested-auth-tree",
    "multi-authorizer",
    "fee-bump-invocation",
    "classic-multi-operation",
]


def find(args):
    url, _ = endpoint(args.rpc)
    candidates = {}
    scanned = []

    def consider(record):
        size = len(json.dumps(record))
        if size > args.max_bytes:
            return
        for case, penalty in cases_of(record).items():
            candidates.setdefault(case, []).append(((penalty, size), record))

    for start in args.start or [rpc(url, "getLatestLedger")["sequence"] - 2000]:
        params = {"startLedger": start, "pagination": {"limit": 200}, "xdrFormat": "json"}
        last = start
        for _ in range(args.pages):
            page = rpc(url, "getTransactions", params)
            for record in page["transactions"]:
                last = record["ledger"]
                consider(record)
            if not page["transactions"]:
                break
            params = {"pagination": {"cursor": page["cursor"], "limit": 200}, "xdrFormat": "json"}
        scanned.append([start, last])
    oz_hashes, event_window = oz_transactions(url)
    for tx_hash in oz_hashes:
        record = rpc(url, "getTransaction", {"hash": tx_hash, "xdrFormat": "json"})
        record["txHash"] = tx_hash
        consider(record)
    picks, used = {}, set()
    for case in PICK_ORDER + sorted(set(candidates) - set(PICK_ORDER)):
        ranked = sorted(
            (pair for pair in candidates.get(case, []) if pair[1]["txHash"] not in used),
            key=lambda pair: pair[0],
        )
        for _, record in ranked[: args.verify]:
            if acceptable(url, case, record):
                picks[case] = {"tx_hash": record["txHash"], "ledger": record["ledger"]}
                used.add(record["txHash"])
                break
    counts = {case: len(found) for case, found in sorted(candidates.items())}
    windows = {"rpc": url, "getTransactions": scanned, "getEvents": event_window, "events": OZ_EVENTS}
    print(json.dumps({"scanned": windows, "counts": counts, "cases": picks}, indent=2))


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def capture(args):
    url, network = endpoint(args.rpc)
    selection = json.loads(Path(args.selection).read_text())
    picks = selection["cases"] if isinstance(selection.get("cases"), dict) else {c["case"]: c for c in selection["cases"]}
    staging = Path(tempfile.mkdtemp(prefix=".captured-mainnet-", dir=CORPUS.parent))
    try:
        manifest = []
        for case in [c for c in CASES if c in picks] + sorted(set(picks) - set(CASES)):
            tx_hash = picks[case]["tx_hash"]
            transaction = rpc(url, "getTransaction", {"hash": tx_hash, "xdrFormat": "base64"})
            if transaction["status"] == "NOT_FOUND":
                raise SystemExit(f"{case}: {tx_hash} is outside this endpoint's retention; the corpus is unchanged")
            decoded = rpc(url, "getTransaction", {"hash": tx_hash, "xdrFormat": "json"})
            write(staging / case / "getNetwork.json", network)
            write(staging / case / "getTransaction.json", transaction)
            contracts = referenced_contracts(decoded["envelopeJson"])
            if len(contracts) > 200:
                raise SystemExit(f"{case}: {len(contracts)} instances need batching; pick another transaction")
            if contracts:
                keys = [instance_key(c) for c in contracts]
                entries = rpc(url, "getLedgerEntries", {"keys": keys, "xdrFormat": "base64"})
                problem = unusable_instances(keys, entries)
                if problem:
                    raise SystemExit(f"{case}: {problem} at ledger {entries['latestLedger']}; the corpus is unchanged")
                write(staging / case / "getLedgerEntries.json", entries)
            manifest.append(
                {
                    "case": case,
                    "tx_hash": tx_hash,
                    "ledger": transaction["ledger"],
                    "status": transaction["status"],
                    "covers": CASES.get(case, picks[case].get("covers", "")),
                }
            )
            print(f"{case}: {tx_hash} ledger {transaction['ledger']} {transaction['status']}", file=sys.stderr)
        header = {"network_passphrase": PASSPHRASE, "protocol_version": network["protocolVersion"]}
        if "scanned" in selection:
            # Where `find` looked, so a case it did not find can be looked for again.
            header["scanned"] = selection["scanned"]
        write(staging / "manifest.json", {**header, "cases": manifest})
        # Swap only now: a case no longer picked leaves with the old corpus.
        retired = CORPUS.with_name(staging.name + "-old")
        if CORPUS.exists():
            CORPUS.rename(retired)
        staging.rename(CORPUS)
        shutil.rmtree(retired, ignore_errors=True)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    finder = sub.add_parser("find")
    finder.add_argument("--rpc", help="mainnet RPC URL (default: Gateway's, then mainnet.sorobanrpc.com)")
    finder.add_argument("--start", type=int, action="append", help="first ledger of a window to scan; repeatable (default: latest - 2000)")
    finder.add_argument("--pages", type=int, default=40, help="getTransactions pages of 200 per window")
    finder.add_argument("--max-bytes", type=int, default=150_000, help="skip larger decoded transactions")
    finder.add_argument("--verify", type=int, default=8, help="candidates per case checked for live instances")
    capturer = sub.add_parser("capture")
    capturer.add_argument("--rpc", help="mainnet RPC URL (default: Gateway's, then mainnet.sorobanrpc.com)")
    capturer.add_argument("selection")
    args = parser.parse_args()
    find(args) if args.command == "find" else capture(args)


if __name__ == "__main__":
    main()
