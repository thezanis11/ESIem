"""Synthetic Wazuh-shaped fixtures, explicitly not captured university traffic."""
from datetime import datetime, timedelta, timezone


def alert(kind, second=0, source="10.77.30.10", asset="files", user="student", **changes):
    definitions = {
        "failure": ("5710", 5, ["syslog", "sshd", "authentication_failed"]),
        "success": ("5715", 3, ["syslog", "sshd", "authentication_success"]),
        "network": ("110001", 10, ["ids", "suricata", "campus"]),
        "integrity": ("110010", 10, ["ossec", "syscheck", "campus"]),
        "normal": ("1002", 2, ["syslog"]),
    }
    rule, level, groups = definitions[kind]
    event = {"timestamp": (datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=second)).isoformat(),
             "id": f"fixture-{kind}-{second}-{source}-{asset}-{user}", "manager": {"name": "lab-manager"},
             "agent": {"name": asset}, "rule": {"id": rule, "level": level, "groups": groups},
             "data": {"srcip": source, "dstuser": user}}
    if kind == "network":
        event["agent"] = {"name": "gateway"}
        event["data"] = {"src_ip": source, "dest_ip": "10.77.50.10" if asset == "files" else "10.77.40.10",
                         "event_type": "alert", "alert": {"signature_id": 2020001, "severity": 1}}
    if kind == "integrity":
        event["data"] = {}
        event["syscheck"] = {"path": "/etc/ssh/sshd_config", "event": "modified"}
    event.update(changes)
    return event


def scenarios():
    fail = [alert("failure", n * 5) for n in range(5)]
    return [
        {"name": "single_typo", "alerts": [alert("failure")], "expected": []},
        {"name": "threshold_four", "alerts": fail[:4], "expected": []},
        {"name": "password_guessing", "alerts": fail, "expected": ["ssh_guessing"]},
        {"name": "successful_login_after_guessing", "alerts": fail + [alert("success", 30)],
         "expected": ["ssh_guessing", "login_after_failures"]},
        {"name": "different_account", "alerts": fail + [alert("success", 30, user="teacher")], "expected": ["ssh_guessing"]},
        {"name": "different_host", "alerts": fail + [alert("success", 30, asset="portal")], "expected": ["ssh_guessing"]},
        {"name": "outside_time_window", "alerts": [alert("failure", n * 70) for n in range(5)], "expected": []},
        {"name": "sensitive_file", "alerts": [alert("integrity")], "expected": ["sensitive_file_change"]},
        {"name": "regular_file", "alerts": [alert("integrity", syscheck={"path": "/var/www/campus/index.html"})], "expected": []},
        {"name": "host_network_agreement", "alerts": [alert("failure"), alert("network", 20)],
         "expected": ["network_alert", "network_host_corroboration"]},
        {"name": "unrelated_network_source", "alerts": [alert("failure"), alert("network", 20, source="10.77.20.99")], "expected": ["network_alert"]},
        {"name": "network_different_asset", "alerts": [alert("failure"), alert("network", 20, asset="portal")], "expected": ["network_alert"]},
        {"name": "login_then_sensitive_file", "alerts": [alert("success"), alert("integrity", 45)],
         "expected": ["sensitive_file_change", "login_then_integrity"]},
        {"name": "unrelated_login_time", "alerts": [alert("success"), alert("integrity", 601)], "expected": ["sensitive_file_change"]},
        {"name": "delayed_authentication", "alerts": [alert("network", 20), alert("failure")],
         "expected": ["network_alert", "network_host_corroboration"]},
        {"name": "normal_activity", "alerts": [alert("normal", n) for n in range(10)], "expected": []},
    ]
