"""Regression evaluation: fixture cases, not field accuracy or malware detection rate."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from campus.engine import Engine
from campus.report import write_report
from tests.fixtures import scenarios


def main():
    assets = json.loads((ROOT / "config/assets.json").read_text())
    results = []
    demo = None
    for case in scenarios():
        engine = Engine(":memory:", assets)
        for event in case["alerts"]:
            engine.ingest(event)
        observed = sorted({i["detection"] for i in engine.incidents()})
        expected = sorted(case["expected"])
        results.append({"case": case["name"], "events": len(case["alerts"]), "expected": expected,
                        "observed": observed, "passed": observed == expected})
        if case["name"] == "successful_login_after_guessing":
            write_report(engine.incidents(), engine.verify_audit(), ROOT / "reports/demo.html")
            demo = case["alerts"]
        engine.close()
    (ROOT / "reports").mkdir(exist_ok=True)
    (ROOT / "reports/regression.json").write_text(json.dumps({"type": "synthetic regression only", "cases": results,
        "passed": sum(c["passed"] for c in results), "total": len(results),
        "real_wazuh_integration_executed": False, "full_lab_executed": False}, indent=2) + "\n")
    (ROOT / "tests/demo-alerts.jsonl").write_text("".join(json.dumps(e) + "\n" for e in demo))
    print(json.dumps({"passed": sum(c["passed"] for c in results), "total": len(results)}))
    if not all(case["passed"] for case in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
