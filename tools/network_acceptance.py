"""Real packet tests in private Linux namespaces, never the host firewall.

Requires root, iproute2, nftables, Suricata and an explicit disposable-lab opt-in.
Only namespaces created by this process are changed or removed.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    if sys.platform != "linux" or os.geteuid() != 0 or os.environ.get("ESIEM_DISPOSABLE_LAB") != "1":
        raise SystemExit("Run as root inside a disposable lab with ESIEM_DISPOSABLE_LAB=1")
    output = ROOT / "runtime/network-acceptance"
    output.mkdir(parents=True, exist_ok=False)
    prefix = "esi" + str(os.getpid())
    namespaces, children = [], []
    results = []
    completed = False
    def command(*args, namespace=None, check=True, input=None):
        argv = (["ip", "netns", "exec", prefix + namespace] if namespace else []) + list(map(str, args))
        result = subprocess.run(argv, input=input, capture_output=True, text=True, timeout=30)
        if check and result.returncode:
            raise RuntimeError(f"Network lab command failed: {result.stderr[-1500:]}")
        return result
    def launch(*args, namespace, log):
        handle = open(output / log, "w")
        child = subprocess.Popen(["ip", "netns", "exec", prefix + namespace, *map(str, args)], stdout=handle, stderr=handle)
        children.append((child, handle))
        return child
    def record(name, passed, **details):
        results.append({"test": name, "passed": bool(passed), **details})
        print(json.dumps(results[-1]), flush=True)
        if not passed:
            raise AssertionError(name)
    def probe(zone, address, port, path=None):
        args = [sys.executable, ROOT / "tools/lab_service.py", "probe-http" if path is not None else "probe-echo", address, "--port", str(port)]
        if path is not None:
            args += ["--path", path]
        return command(*args, namespace=zone, check=False).returncode == 0
    def stop(child):
        child.terminate()
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
    def alerts(folder):
        path = output / folder / "eve.json"
        if not path.exists():
            return []
        parsed = []
        for line in path.read_text().splitlines():
            try:
                event = json.loads(line)
                if event.get("event_type") == "alert":
                    parsed.append(event)
            except json.JSONDecodeError:
                continue
        return parsed
    try:
        for zone in ("gw", "student", "staff", "portal", "files", "management", "wan"):
            command("ip", "netns", "add", prefix + zone)
            namespaces.append(prefix + zone)
            command("ip", "link", "set", "lo", "up", namespace=zone)
        links = [("student", "ens5", "10.77.20.10", "10.77.20.1"), ("staff", "ens6", "10.77.30.10", "10.77.30.1"),
                 ("portal", "ens7", "10.77.40.10", "10.77.40.1"), ("files", "ens8", "10.77.50.10", "10.77.50.1"),
                 ("management", "ens4", "10.77.10.50", "10.77.10.1"), ("wan", "ens3", "192.0.2.10", "192.0.2.2")]
        for index, (zone, interface, address, gateway) in enumerate(links):
            a, b = "v" + prefix + str(index), "p" + prefix + str(index)
            command("ip", "link", "add", a, "type", "veth", "peer", "name", b)
            command("ip", "link", "set", a, "netns", prefix + "gw")
            command("ip", "link", "set", b, "netns", prefix + zone)
            command("ip", "link", "set", a, "name", interface, namespace="gw")
            command("ip", "address", "add", gateway + "/24", "dev", interface, namespace="gw")
            command("ip", "link", "set", interface, "up", namespace="gw")
            command("ip", "link", "set", b, "name", "eth0", namespace=zone)
            command("ip", "address", "add", address + "/24", "dev", "eth0", namespace=zone)
            command("ip", "link", "set", "eth0", "up", namespace=zone)
            command("ip", "route", "add", "default", "via", gateway, namespace=zone)
        command("ip", "address", "add", "10.77.10.10/24", "dev", "eth0", namespace="management")
        command("sysctl", "-w", "net.ipv4.ip_forward=1", namespace="gw")
        command("nft", "-f", ROOT / "infra/gateway/campus.nft", namespace="gw")
        service = ROOT / "tools/lab_service.py"
        launch(sys.executable, service, "http", "10.77.40.10", "--port", "80", namespace="portal", log="portal.log")
        launch(sys.executable, service, "echo", "10.77.50.10", "--port", "22", namespace="files", log="files.log")
        launch(sys.executable, service, "echo", "10.77.10.10", "--port", "1514", namespace="management", log="telemetry.log")
        time.sleep(1)
        record("student_to_portal_allowed", probe("student", "10.77.40.10", 80, "/"))
        record("student_to_files_denied", not probe("student", "10.77.50.10", 22))
        record("staff_to_files_allowed", probe("staff", "10.77.50.10", 22))
        record("wan_to_portal_denied", not probe("wan", "10.77.40.10", 80, "/"))
        record("agent_telemetry_allowed", probe("student", "10.77.10.10", 1514))
        config = output / "suricata.yaml"
        command(sys.executable, ROOT / "infra/gateway/configure_suricata.py", "--base", "/etc/suricata/suricata.yaml", "--output", config)
        command("suricata", "-T", "-c", config, "-S", ROOT / "infra/gateway/campus.rules")
        for folder in ("ids", "ips"):
            (output / folder).mkdir()
        # veth offloading exposes partial checksums to packet capture. Disable
        # capture checksum validation only for this deterministic virtual lab.
        common = ["suricata", "-c", config, "-S", ROOT / "infra/gateway/campus.rules", "-k", "none",
                  "--set", "unix-command.enabled=no"]
        ids = launch(*common, "--runmode", "single", "-i", "ens7", "-l", output / "ids", namespace="gw", log="ids-engine.log")
        time.sleep(3)
        record("ids_service_running", ids.poll() is None)
        record("ids_marker_passes", probe("student", "10.77.40.10", 80, "/campus-ids-test"))
        record("ids_drop_rule_is_passive", probe("student", "10.77.40.10", 80, "/campus-ips-test"))
        time.sleep(2)
        stop(ids)
        record("ids_alerts_observed", {9900001, 9900002}.issubset({e["alert"]["signature_id"] for e in alerts("ids")}))
        ips = launch(*common, "-q", "0", "-l", output / "ips", namespace="gw", log="ips-engine.log")
        time.sleep(3)
        record("ips_service_running", ips.poll() is None)
        command("nft", "add", "rule", "inet", "campus", "ips", "queue", "num", "0", namespace="gw")
        record("ips_baseline_passes", probe("student", "10.77.40.10", 80, "/"))
        record("ips_marker_blocked", not probe("student", "10.77.40.10", 80, "/campus-ips-test"))
        time.sleep(2)
        stop(ips)
        record("ips_block_evidence", any(e["alert"]["signature_id"] == 9900002 and e["alert"]["action"] == "blocked" for e in alerts("ips")))
        record("queue_fails_closed", not probe("student", "10.77.40.10", 80, "/"))
        command("nft", "flush", "chain", "inet", "campus", "ips", namespace="gw")
        record("queue_rollback_restores_traffic", probe("student", "10.77.40.10", 80, "/"))
        policy = json.loads((ROOT / "config/response-policy.json").read_text())
        policy["execute"] = True
        policy_path = output / "response-policy.json"
        policy_path.write_text(json.dumps(policy))
        policy_path.chmod(0o600)
        message = {"command": "add", "parameters": {"alert": {"rule": {"id": "110001"}, "data": {"srcip": "10.77.20.10"}}}}
        command(sys.executable, ROOT / "campus/response.py", "--policy", policy_path, "--log", output / "response.log",
                namespace="gw", input=json.dumps(message) + "\n")
        started = time.monotonic()
        record("quarantine_blocks_endpoint", not probe("student", "10.77.40.10", 80, "/"))
        record("quarantine_preserves_telemetry", probe("student", "10.77.10.10", 1514))
        message["parameters"]["alert"]["data"]["srcip"] = "10.77.10.10"
        rejected = command(sys.executable, ROOT / "campus/response.py", "--policy", policy_path, "--log", output / "response.log",
                           namespace="gw", input=json.dumps(message) + "\n", check=False)
        record("protected_address_rejected", rejected.returncode != 0)
        while time.monotonic() - started < 302:
            print("Waiting for the real 300-second kernel isolation lease to expire", flush=True)
            time.sleep(min(30, 302 - (time.monotonic() - started)))
        record("quarantine_expires_automatically", probe("student", "10.77.40.10", 80, "/"))
        captured = alerts("ids") + alerts("ips")
        (ROOT / "reports/local-captured-eve.jsonl").write_text("".join(json.dumps(e) + "\n" for e in captured))
        completed = True
    finally:
        (ROOT / "reports/local-network-acceptance.json").write_text(json.dumps({"real_packets": True, "completed": completed, "expected_tests": 19,
            "engine": "Linux namespaces + nftables + Suricata", "tests": results}, indent=2))
        for child, handle in children:
            if child.poll() is None:
                stop(child)
            handle.close()
        for namespace in reversed(namespaces):
            command("ip", "netns", "delete", namespace, check=False)


if __name__ == "__main__":
    main()
