"""Real Wazuh transport/indexer/dashboard acceptance, with labelled test log injection.

The endpoint runs a genuine agent; no university credentials or live attacks used.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from campus.engine import Engine


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manager-only", action="store_true")
    args = parser.parse_args()
    compose = ["docker", "compose", "-p", "campussentinel", "-f", "runtime/soc/docker-compose.yml"]
    results = []
    def command(argv, check=True, input=None, timeout=45):
        result = subprocess.run(argv, input=input, text=True, capture_output=True, timeout=timeout)
        if check and result.returncode:
            # Never include the argument list: it can contain private data in future callers.
            raise RuntimeError("Lab command failed: " + result.stderr[-1000:])
        return result
    def manager(*argv, **kwargs):
        return command(compose + ["exec", "-T", "wazuh.manager", *argv], **kwargs)
    def record(name, passed, **details):
        results.append({"test": name, "passed": bool(passed), **details})
        print(json.dumps(results[-1]), flush=True)
        if not passed:
            raise AssertionError(name)
    def wait_for(name, callback, timeout=240):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            try:
                if callback():
                    record(name, True)
                    return
            except (ValueError, RuntimeError, subprocess.TimeoutExpired):
                pass
            time.sleep(4)
        record(name, False)
    try:
        wait_for("manager_analysis_running", lambda: "wazuh-analysisd is running" in manager("/var/ossec/bin/wazuh-control", "status", check=False).stdout)
        command([sys.executable, "tools/test_wazuh.py"])
        record("native_rules_and_decoders", True)
        if not args.manager_only:
            index_command = 'curl --silent --fail --cacert /etc/ssl/root-ca.pem -u "$INDEXER_USERNAME:$INDEXER_PASSWORD" https://wazuh.indexer:9200/_cluster/health'
            wait_for("indexer_authenticated_tls", lambda: json.loads(manager("bash", "-c", index_command).stdout).get("status") in ("green", "yellow"))
            dashboard_command = 'curl --silent --fail --cacert /etc/ssl/root-ca.pem -u "$INDEXER_USERNAME:$INDEXER_PASSWORD" https://wazuh.dashboard:5601/api/status'
            wait_for("dashboard_authenticated_tls", lambda: manager("bash", "-c", dashboard_command, check=False).returncode == 0, timeout=300)
        endpoint = ROOT / "runtime/test-endpoint"
        endpoint.mkdir(parents=True, exist_ok=True)
        (endpoint / "auth.log").touch()
        (endpoint / "eve.json").touch()
        watched = endpoint / "watched"
        watched.mkdir(exist_ok=True)
        (watched / "esiem_lab").write_text("# ESIem baseline; no privileges granted\n")
        manager("/var/ossec/bin/manage_agents", "-a", "any", "-n", "files")
        # A fresh disposable manager owns this one test endpoint. Keys are never printed.
        keys = manager("cat", "/var/ossec/etc/client.keys").stdout
        (endpoint / "client.keys").write_text(keys)
        (endpoint / "client.keys").chmod(0o600)
        first = keys.strip().splitlines()[-1].split()[0]
        configuration = '''<ossec_config><client><server><address>wazuh.manager</address><port>1514</port><protocol>tcp</protocol></server><enrollment><enabled>no</enabled></enrollment></client>
<localfile><log_format>syslog</log_format><location>/var/log/esiem/auth.log</location></localfile>
<localfile><log_format>json</log_format><location>/var/log/esiem/eve.json</location></localfile>
<syscheck><disabled>no</disabled><frequency>60</frequency><scan_on_start>yes</scan_on_start><directories check_all="yes" realtime="yes" report_changes="no">/etc/sudoers.d</directories></syscheck></ossec_config>'''
        (endpoint / "agent.conf").write_text(configuration)
        command(["docker", "run", "-d", "--name", "esiem-test-agent", "--hostname", "files", "--network", "campussentinel_soc",
                 "-e", "WAZUH_MANAGER_SERVER=wazuh.manager", "-v", f"{endpoint / 'agent.conf'}:/wazuh-config-mount/etc/ossec.conf:ro",
                 "-v", f"{endpoint / 'client.keys'}:/wazuh-config-mount/etc/client.keys:ro", "-v", f"{endpoint}:/var/log/esiem",
                 "-v", f"{watched}:/etc/sudoers.d", "wazuh/wazuh-agent:4.14.10"], timeout=240)
        wait_for("agent_authenticated_online", lambda: "Active" in manager("/var/ossec/bin/agent_control", "-i", first).stdout, timeout=150)
        time.sleep(12)  # Allow the initial integrity scan to settle before changing a file.
        now = datetime.now(timezone.utc)
        # Actual agent transport and native decoding, explicitly synthetic SSH log lines.
        with (endpoint / "auth.log").open("a") as log:
            for index in range(6):
                log.write(now.strftime("%b %d %H:%M:%S") + f" files sshd[{4200+index}]: Invalid user esiem_student from 10.77.30.10 port {51000+index}\n")
        event = {"timestamp": now.isoformat(), "event_type": "alert", "src_ip": "10.77.30.10", "dest_ip": "10.77.50.10",
                 "alert": {"signature_id": 9900002, "signature": "ESIem labelled transport test", "severity": 3, "action": "blocked"}}
        with (endpoint / "eve.json").open("a") as log:
            log.write(json.dumps(event) + "\n")
        with (watched / "esiem_lab").open("a") as target:
            target.write("# ESIem changed comment; no privileges granted\n")
        def read_alerts():
            result = manager("cat", "/var/ossec/logs/alerts/alerts.json", check=False)
            parsed = []
            for line in result.stdout.splitlines():
                try:
                    alert = json.loads(line)
                    if alert.get("agent", {}).get("name") == "files":
                        parsed.append(alert)
                except json.JSONDecodeError:
                    continue
            return parsed
        wait_for("ssh_events_received", lambda: sum("authentication_failed" in a.get("rule", {}).get("groups", []) for a in read_alerts()) >= 5, timeout=100)
        wait_for("eve_event_decoded", lambda: any(str(a.get("rule", {}).get("id")) == "110003" for a in read_alerts()), timeout=100)
        wait_for("integrity_event_received", lambda: any(str(a.get("rule", {}).get("id")) == "110010" for a in read_alerts()), timeout=100)
        engine = Engine(":memory:", json.loads((ROOT / "config/assets.json").read_text()))
        for alert in read_alerts():
            engine.ingest(alert)
        detections = {i["detection"] for i in engine.incidents()}
        record("native_alerts_correlated", {"ssh_guessing", "network_alert", "network_host_corroboration", "sensitive_file_change"}.issubset(detections), observed=sorted(detections))
        (ROOT / "reports/local-live-correlation.json").write_text(json.dumps({"provenance": "real agent transport; synthetic test log injection and real file modification",
            "incidents": engine.incidents(), "audit": engine.verify_audit()}, indent=2))
        engine.close()
        if not args.manager_only:
            query = 'curl --silent --fail --cacert /etc/ssl/root-ca.pem -u "$INDEXER_USERNAME:$INDEXER_PASSWORD" "https://wazuh.indexer:9200/wazuh-alerts-*/_count?q=rule.id:110003"'
            wait_for("alert_indexed_and_searchable", lambda: json.loads(manager("bash", "-c", query).stdout).get("count", 0) >= 1, timeout=150)
    finally:
        (ROOT / "reports/local-stack-acceptance.json").write_text(json.dumps({"profile": "manager-only" if args.manager_only else "full-stack",
            "provenance": "real native Wazuh services and agent; labelled test logs", "tests": results}, indent=2))


if __name__ == "__main__":
    main()
