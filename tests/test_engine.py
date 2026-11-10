import copy
import json
from pathlib import Path
import random
import tempfile
import unittest

from campus.engine import Engine, normalize
from campus.report import write_report
from campus.response import plan
from tests.fixtures import alert, scenarios

ROOT = Path(__file__).resolve().parents[1]
ASSETS = json.loads((ROOT / "config/assets.json").read_text())
(ROOT / ".cache").mkdir(exist_ok=True)


class CorrelationTests(unittest.TestCase):
    def setUp(self):
        self.engine = Engine(":memory:", ASSETS)

    def tearDown(self):
        self.engine.close()

    def test_all_positive_and_negative_scenarios(self):
        for case in scenarios():
            with self.subTest(case=case["name"]):
                engine = Engine(":memory:", ASSETS)
                for event in case["alerts"]:
                    engine.ingest(event)
                self.assertEqual(set(case["expected"]), {i["detection"] for i in engine.incidents()})
                engine.verify_audit()
                engine.close()

    def test_duplicates_cannot_create_brute_force(self):
        event = alert("failure")
        self.assertTrue(self.engine.ingest(event))
        for _ in range(20):
            self.assertFalse(self.engine.ingest(event))
        self.assertEqual([], self.engine.incidents())

    def test_four_sources_do_not_merge(self):
        for n in range(10):
            self.engine.ingest(alert("failure", n, source=f"10.77.20.{n+10}"))
        self.assertEqual([], self.engine.incidents())

    def test_timezone_required(self):
        with self.assertRaises(ValueError):
            self.engine.ingest(alert("failure", timestamp="2026-01-01T01:00:00"))

    def test_invalid_source_address_rejected(self):
        with self.assertRaises(ValueError):
            self.engine.ingest(alert("failure", source="10.0.0.1; rm -rf /"))

    def test_missing_agent_cannot_merge_unrelated_hosts(self):
        with self.assertRaisesRegex(ValueError, "agent name"):
            self.engine.ingest(alert("failure", agent={}))

    def test_network_destination_required(self):
        event = alert("network")
        del event["data"]["dest_ip"]
        with self.assertRaisesRegex(ValueError, "destination"):
            self.engine.ingest(event)

    def test_stale_event_rejected_explicitly(self):
        self.engine.ingest(alert("normal", 90000))
        with self.assertRaisesRegex(ValueError, "watermark"):
            self.engine.ingest(alert("failure", 0))

    def test_order_independence_for_complete_short_case(self):
        events = [alert("failure", n * 5) for n in range(5)] + [alert("success", 30), alert("network", 40), alert("integrity", 50)]
        expected = None
        for seed in range(6):
            engine = Engine(":memory:", ASSETS)
            shuffled = events[:]
            random.Random(seed).shuffle(shuffled)
            for event in shuffled:
                engine.ingest(event)
            result = {(i["detection"], i["asset"]) for i in engine.incidents()}
            if expected is not None:
                self.assertEqual(expected, result)
            expected = result
            engine.close()

    def test_restart_preserves_deduplication_and_audit(self):
        with tempfile.TemporaryDirectory(dir=ROOT / ".cache") as tmp:
            db = str(Path(tmp) / "state.db")
            first = Engine(db, ASSETS)
            event = alert("integrity")
            first.ingest(event)
            head = first.verify_audit()
            first.close()
            second = Engine(db, ASSETS)
            self.assertFalse(second.ingest(event))
            self.assertEqual(head, second.verify_audit())
            second.close()

    def test_tampering_detected(self):
        self.engine.ingest(alert("integrity"))
        self.engine.db.execute("UPDATE audit SET payload='{}' WHERE seq=1")
        with self.assertRaisesRegex(ValueError, "broken"):
            self.engine.verify_audit()

    def test_incident_table_tampering_detected(self):
        self.engine.ingest(alert("integrity"))
        self.engine.db.execute("UPDATE incidents SET payload='{}'")
        with self.assertRaises((ValueError, KeyError)):
            self.engine.verify_audit()

    def test_earlier_delayed_failure_does_not_duplicate_episode(self):
        for second in (5, 10, 15, 20, 25, 0):
            self.engine.ingest(alert("failure", second))
        self.assertEqual(1, len(self.engine.incidents()))
        self.engine.verify_audit()

    def test_report_escapes_untrusted_fields(self):
        self.engine.ingest(alert("integrity", asset='<script>alert(1)</script>'))
        with tempfile.TemporaryDirectory(dir=ROOT / ".cache") as tmp:
            output = Path(tmp) / "index.html"
            write_report(self.engine.incidents(), self.engine.verify_audit(), output)
            text = output.read_text(encoding="utf-8")
            self.assertNotIn("<script>alert(1)</script>", text)
            self.assertIn("&lt;script&gt;", text)


class ResponseTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads((ROOT / "config/response-policy.json").read_text())

    def test_default_simulates_scoped_expiring_isolation(self):
        proposal = plan(alert("network", source="10.77.20.10"), self.policy)
        self.assertEqual("dry-run", proposal["mode"])
        self.assertEqual(300, proposal["ttl_seconds"])

    def test_protected_and_external_addresses_rejected(self):
        for ip in ("10.77.10.10", "10.77.20.1", "8.8.8.8", "10.77.30.10", "10.77.20.255", "::1"):
            with self.subTest(ip=ip), self.assertRaises(ValueError):
                plan(alert("network", source=ip), self.policy)

    def test_unapproved_rule_rejected(self):
        with self.assertRaises(ValueError):
            plan(alert("failure"), self.policy)

    def test_ttl_cannot_be_silently_extended(self):
        self.policy["timeout_seconds"] = 3600
        with self.assertRaises(ValueError):
            plan(alert("network"), self.policy)


if __name__ == "__main__":
    unittest.main()
