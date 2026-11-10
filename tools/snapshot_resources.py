"""Read-only cgroup evidence for a running ESIem acceptance deployment."""
import json
from pathlib import Path
import platform
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    containers = ["campussentinel-wazuh.manager-1", "campussentinel-wazuh.indexer-1", "campussentinel-wazuh.dashboard-1", "esiem-test-agent"]
    report = {"kernel": platform.release(), "measurement": "Container-lifetime peak memory and OOM counters, not a throughput benchmark", "containers": {}}
    for name in containers:
        raw = subprocess.check_output(["docker", "inspect", "--format", "{{json .State}} {{.RestartCount}}", name], text=True)
        state_json, _, restart_count = raw.rpartition(" ")
        state = json.loads(state_json)
        events = subprocess.check_output(["docker", "exec", name, "cat", "/sys/fs/cgroup/memory.events"], text=True)
        counters = {line.split()[0]: int(line.split()[1]) for line in events.splitlines()}
        peak = int(subprocess.check_output(["docker", "exec", name, "cat", "/sys/fs/cgroup/memory.peak"], text=True))
        report["containers"][name] = {"running": state["Running"], "pid1_oom_killed": state["OOMKilled"],
            "restart_count": int(restart_count), "oom_kills": counters["oom_kill"], "peak_memory_bytes": peak}
    report["stable"] = all(v["running"] and not v["pid1_oom_killed"] and v["oom_kills"] == 0 and v["restart_count"] == 0 for v in report["containers"].values())
    (ROOT / "reports/local-resource-snapshot.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    if not report["stable"]:
        raise SystemExit("The lab experienced an OOM or restart; compact profile is not validated")


if __name__ == "__main__":
    main()
