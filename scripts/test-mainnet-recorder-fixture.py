#!/usr/bin/env python3
"""Tests for scripts/mainnet-recorder-fixture.py that need no network: which transactions
qualify for a corpus case, and that a capture whose instances the recorder would refuse leaves
the committed corpus as it was."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

SCRIPT = Path(__file__).resolve().parent / "mainnet-recorder-fixture.py"
spec = importlib.util.spec_from_file_location("mainnet_recorder_fixture", SCRIPT)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)

CONTRACT = "CAQKMRIU2D2UPW3ACRGUNAALAMYV4DX45BQUPSJ4TQAW5BK3RFOZGORK"
SOURCE = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7"
PAYER = "GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H"


def transfer(kind, fee_source=PAYER, credentials="source_account"):
    """A successful transfer, authorized by the source-account credential unless `credentials`
    says otherwise, in a plain envelope or one fee-bumped by `fee_source`."""
    call = {"contract_address": CONTRACT, "function_name": "transfer", "args": []}
    tx = {
        "source_account": SOURCE,
        "operations": [
            {
                "body": {
                    "invoke_host_function": {
                        "host_function": {"invoke_contract": call},
                        "auth": [
                            {
                                "credentials": credentials,
                                "root_invocation": {"function": {"contract_fn": call}, "sub_invocations": []},
                            }
                        ],
                    }
                }
            }
        ],
    }
    if kind == "tx":
        envelope = {"tx": {"tx": tx}}
    else:
        envelope = {"tx_fee_bump": {"tx": {"fee_source": fee_source, "inner_tx": {"tx": {"tx": tx}}}}}
    return {"status": "SUCCESS", "envelopeJson": envelope}


class CaseEligibility(unittest.TestCase):
    def test_only_a_fee_bumped_transfer_is_the_source_account_transfer_case(self):
        # The case's test requires TxFeeBump: a plain envelope must not be picked for it.
        self.assertNotIn("sac-transfer-source-account", fixture.cases_of(transfer("tx")))
        self.assertEqual(fixture.cases_of(transfer("tx_fee_bump"))["sac-transfer-source-account"], 0)

    def test_a_fee_bump_paid_by_the_inner_source_is_no_fee_bump_case(self):
        # Both fee-bump cases' tests require a fee payer other than the inner source.
        found = fixture.cases_of(transfer("tx_fee_bump", fee_source=SOURCE))
        self.assertNotIn("sac-transfer-source-account", found)
        self.assertNotIn("fee-bump-invocation", found)

    def test_muxed_fee_source_and_classic_inner_source_are_the_same_account(self):
        # SEP-23 canonical and muxed encodings of the same public key.
        classic = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ"
        muxed = "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUQ"
        for inner, payer in [(classic, muxed), (muxed, classic)]:
            record = transfer("tx_fee_bump", fee_source=payer)
            fixture.inner(record["envelopeJson"])[1]["source_account"] = inner
            found = fixture.cases_of(record)
            self.assertNotIn("sac-transfer-source-account", found)
            self.assertNotIn("fee-bump-invocation", found)

    def test_a_fee_payer_that_is_the_operation_source_authorizes_the_call(self):
        record = transfer("tx_fee_bump")
        fixture.inner(record["envelopeJson"])[1]["operations"][0]["source_account"] = PAYER
        found = fixture.cases_of(record)
        self.assertNotIn("fee-bump-invocation", found)
        self.assertNotIn("sac-transfer-source-account", found)

    def test_a_fee_payer_that_authorizes_the_call_is_no_fee_bump_case(self):
        # fee-bump-invocation's test requires that the fee payer authorizes nothing.
        paid = transfer("tx_fee_bump", credentials={"address": {"address": PAYER}})
        self.assertNotIn("fee-bump-invocation", fixture.cases_of(paid))
        self.assertIn("fee-bump-invocation", fixture.cases_of(transfer("tx_fee_bump")))


class InstanceCheck(unittest.TestCase):
    def setUp(self):
        self.key = fixture.instance_key(CONTRACT)

    def test_an_instance_left_out_of_the_answer_is_refused(self):
        self.assertIn("missing", fixture.unusable_instances([self.key], {"entries": [], "latestLedger": 10}))

    def test_an_archived_instance_is_refused(self):
        answer = {"entries": [{"key": self.key, "liveUntilLedgerSeq": 9}], "latestLedger": 10}
        self.assertIn("archived", fixture.unusable_instances([self.key], answer))

    def test_an_unrequested_or_repeated_key_is_refused(self):
        other = fixture.instance_key("CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE")
        live = {"key": self.key, "liveUntilLedgerSeq": 20}
        extra = {"entries": [live, {"key": other, "liveUntilLedgerSeq": 20}], "latestLedger": 10}
        self.assertIn("unrequested", fixture.unusable_instances([self.key], extra))
        twice = {"entries": [live, live], "latestLedger": 10}
        self.assertIn("more than once", fixture.unusable_instances([self.key], twice))

    def test_every_committed_capture_passes(self):
        corpus = sorted(fixture.CORPUS.glob("*/getLedgerEntries.json"))
        self.assertTrue(corpus)
        for path in corpus:
            answer = json.loads(path.read_text())
            keys = [entry["key"] for entry in answer["entries"]]
            with self.subTest(case=path.parent.name):
                self.assertIsNone(fixture.unusable_instances(keys, answer))


class Capture(unittest.TestCase):
    def test_a_missing_instance_leaves_the_corpus_unchanged(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus = root / "captured-mainnet"
            (corpus / "kept").mkdir(parents=True)
            (corpus / "kept" / "marker").write_text("old corpus\n")
            selection = root / "selection.json"
            selection.write_text(json.dumps({"cases": {"sac-transfer-source-account": {"tx_hash": "ab" * 32}}}))

            def rpc(url, method, params=None):
                if method == "getTransaction" and params["xdrFormat"] == "base64":
                    return {"status": "SUCCESS", "ledger": 5}
                if method == "getTransaction":
                    return transfer("tx_fee_bump")
                if method == "getLedgerEntries":
                    return {"entries": [], "latestLedger": 10}
                raise AssertionError(method)

            saved = fixture.CORPUS, fixture.rpc, fixture.endpoint
            fixture.CORPUS, fixture.rpc = corpus, rpc
            fixture.endpoint = lambda requested: ("rpc", {"protocolVersion": 30})
            try:
                with self.assertRaises(SystemExit) as refused:
                    fixture.capture(SimpleNamespace(rpc=None, selection=str(selection)))
            finally:
                fixture.CORPUS, fixture.rpc, fixture.endpoint = saved
            self.assertIn("corpus is unchanged", str(refused.exception))
            self.assertEqual((corpus / "kept" / "marker").read_text(), "old corpus\n")
            self.assertEqual(sorted(p.name for p in root.iterdir()), ["captured-mainnet", "selection.json"])


if __name__ == "__main__":
    unittest.main()
