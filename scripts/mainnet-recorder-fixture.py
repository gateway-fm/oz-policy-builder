#!/usr/bin/env python3
"""Find and capture the mainnet transactions behind the recorder's fixture corpus.

Public RPC serves `getTransaction` only inside its retention window (about seven days on
mainnet), so a transaction worth keeping has to be captured while it is still served. This
script does both halves, read-only, against a public mainnet RPC:

  find [--rpc URL] [--start LEDGER ...] [--pages N]
      Scan `getTransactions` (decoded with `xdrFormat: json`) forward from each START, plus
      the transactions behind OpenZeppelin smart-account events (`getEvents`) across the
      retention window, and print, as JSON, one distinct transaction per corpus case found.
      Every referenced contract instance must still be live. Nothing is written.
  capture [--rpc URL] SELECTION.json
      For each case in SELECTION (the output of `find`, or the committed manifest, to refresh
      the same transactions while they are retained), store the verbatim `result` of every
      call the recorder's acquisition path makes for it: `getNetwork`, `getTransaction`
      (base64, as `ozpb_source_rpc::get_transaction` asks), and `getLedgerEntries` for the
      contract instances the transaction references. Then write the manifest.

Nothing is signed, simulated or submitted. Every value stored is public ledger data. Run with
`python3 -I`; it imports only the standard library.
"""
import argparse
import base64
import json
import sys
import time
import urllib.request
from pathlib import Path

PASSPHRASE = "Public Global Stellar Network ; September 2015"
DEFAULT_RPC = "https://mainnet.sorobanrpc.com"
ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "crates/source-rpc/tests/captured-mainnet"
USER_AGENT = "ozpb-fixture-capture/1"

# Case name -> what the fixture exercises. The order is the manifest's order.
CASES = {
    "sac-transfer-source-account": "Stellar Asset Contract transfer invoked by a G-account and authorized by the source-account credential",
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
                raise SystemExit(f"{method}: {error}")
            time.sleep(2 * (attempt + 1))
    if "error" in reply:
        raise SystemExit(f"{method}: {reply['error']}")
    return reply["result"]


def strkey_payload(address):
    raw = base64.b32decode(address + "=" * (-len(address) % 8))
    return raw[1:33]


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
    invokes = [op["body"]["invoke_host_function"] for op in operations if arm(op["body"]) == "invoke_host_function"]
    found = {}
    if not invokes:
        if success and kind == "tx" and 2 <= len(operations) <= 4:
            found["classic-multi-operation"] = 0
        return found
    invoke = invokes[0]
    host = invoke["host_function"]
    auth = invoke["auth"]
    call = host.get("invoke_contract") if isinstance(host, dict) else None
    arms = [arm(entry["credentials"]) for entry in auth]
    authorizers = [credential_address(entry["credentials"]) or tx["source_account"] for entry in auth]
    plain = 0 if kind == "tx" else 1  # a plain envelope keeps each case apart from the fee bump
    if not success:
        if call:
            found["failed-invocation"] = plain
        return found
    if kind == "tx_fee_bump":
        # The relayer pattern: one party pays the fee, another authorizes the call.
        found["fee-bump-invocation"] = 0 if "address" in arms else 1
    if call and call["function_name"] == "transfer" and arms == ["source_account"]:
        found["sac-transfer-source-account"] = plain
    if arms == ["address"] and authorizers[0].startswith("G") and authorizers[0] != tx["source_account"]:
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
    if len(set(authorizers)) >= 2:
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
    oldest = rpc(url, "getHealth")["oldestLedger"]
    filters = [{"type": "contract", "topics": [[symbol_topic(n), "**"]]} for n in OZ_EVENTS]
    params = {"startLedger": oldest + 100, "filters": filters, "pagination": {"limit": 1000}}
    hashes = []
    while True:
        page = rpc(url, "getEvents", params)
        hashes += [e["txHash"] for e in page["events"] if e["txHash"] not in hashes]
        if int(page["cursor"].split("-")[0]) >> 32 >= page["latestLedger"]:
            return hashes
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
    url = args.rpc
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
    for tx_hash in oz_transactions(url):
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
    print(json.dumps({"scanned": scanned, "counts": counts, "cases": picks}, indent=2))


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def capture(args):
    url = args.rpc
    selection = json.loads(Path(args.selection).read_text())
    picks = selection["cases"] if isinstance(selection.get("cases"), dict) else {c["case"]: c for c in selection["cases"]}
    network = rpc(url, "getNetwork")
    if network["passphrase"] != PASSPHRASE:
        raise SystemExit(f"{url} is not mainnet: {network['passphrase']}")
    manifest = []
    for case in [c for c in CASES if c in picks] + sorted(set(picks) - set(CASES)):
        tx_hash = picks[case]["tx_hash"]
        directory = CORPUS / case
        transaction = rpc(url, "getTransaction", {"hash": tx_hash, "xdrFormat": "base64"})
        if transaction["status"] == "NOT_FOUND":
            raise SystemExit(f"{case}: {tx_hash} is outside this endpoint's retention")
        decoded = rpc(url, "getTransaction", {"hash": tx_hash, "xdrFormat": "json"})
        write(directory / "getNetwork.json", network)
        write(directory / "getTransaction.json", transaction)
        contracts = referenced_contracts(decoded["envelopeJson"])
        entries = directory / "getLedgerEntries.json"
        if contracts:
            if len(contracts) > 200:
                raise SystemExit(f"{case}: {len(contracts)} instances need batching; pick another transaction")
            write(entries, rpc(url, "getLedgerEntries", {"keys": [instance_key(c) for c in contracts], "xdrFormat": "base64"}))
        elif entries.exists():
            entries.unlink()
        item = {
            "case": case,
            "tx_hash": tx_hash,
            "ledger": transaction["ledger"],
            "status": transaction["status"],
            "covers": CASES.get(case, picks[case].get("covers", "")),
        }
        manifest.append(item)
        print(f"{case}: {tx_hash} ledger {transaction['ledger']} {transaction['status']}", file=sys.stderr)
    write(
        CORPUS / "manifest.json",
        {"network_passphrase": PASSPHRASE, "protocol_version": network["protocolVersion"], "cases": manifest},
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    finder = sub.add_parser("find")
    finder.add_argument("--rpc", default=DEFAULT_RPC)
    finder.add_argument("--start", type=int, action="append", help="first ledger of a window to scan; repeatable (default: latest - 2000)")
    finder.add_argument("--pages", type=int, default=40, help="getTransactions pages of 200 per window")
    finder.add_argument("--max-bytes", type=int, default=150_000, help="skip larger decoded transactions")
    finder.add_argument("--verify", type=int, default=8, help="candidates per case checked for live instances")
    capturer = sub.add_parser("capture")
    capturer.add_argument("--rpc", default=DEFAULT_RPC)
    capturer.add_argument("selection")
    args = parser.parse_args()
    find(args) if args.command == "find" else capture(args)


if __name__ == "__main__":
    main()
