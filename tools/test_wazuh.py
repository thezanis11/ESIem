"""Run real wazuh-logtest inside the deployed manager. Requires a running stack."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--compose", default="runtime/soc/docker-compose.yml")
    args = parser.parse_args()
    compose = ["docker", "compose", "-p", "campussentinel", "-f", args.compose, "exec", "-T", "wazuh.manager"]
    check = subprocess.run(compose + ["/var/ossec/bin/wazuh-analysisd", "-t"], capture_output=True, text=True)
    if check.returncode:
        print(check.stdout + check.stderr)
        raise SystemExit(check.returncode)
    samples = [
        ("ssh_invalid_user", "5710:5:sshd", "Jan 01 00:00:00 files sshd[123]: Invalid user nonexistent from 10.77.20.10 port 50000"),
        ("priority_suricata", "110001:10:json", json.dumps({"timestamp": "2026-01-01T00:00:00+0000", "event_type": "alert", "src_ip": "10.77.20.10", "dest_ip": "10.77.40.10", "alert": {"signature_id": 2020001, "signature": "Integration test", "severity": 1}})),
        ("ids_marker", "110002:8:json", json.dumps({"timestamp": "2026-01-01T00:00:00+0000", "event_type": "alert", "alert": {"signature_id": 9900001, "signature": "IDS marker", "severity": 3}})),
        ("ips_marker", "110003:10:json", json.dumps({"timestamp": "2026-01-01T00:00:00+0000", "event_type": "alert", "alert": {"signature_id": 9900002, "signature": "IPS marker", "severity": 3}})),
        ("normal_suricata_alert", "86601:3:json", json.dumps({"timestamp": "2026-01-01T00:00:00+0000", "event_type": "alert", "alert": {"signature_id": 1, "signature": "Low priority", "severity": 3}})),
    ]
    results = []
    for name, expected, line in samples:
        result = subprocess.run(compose + ["/var/ossec/bin/wazuh-logtest", "-U", expected],
                                input=line + "\n", capture_output=True, text=True, timeout=30)
        results.append({"test": name, "expected": expected, "passed": result.returncode == 0})
        if result.returncode:
            print(result.stdout + result.stderr, file=sys.stderr)
    output = ROOT / "reports/local-wazuh-integration.json"
    output.write_text(json.dumps({"native_engine": True, "tests": results}, indent=2) + "\n")
    print(json.dumps(results, indent=2))
    if not all(r["passed"] for r in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
