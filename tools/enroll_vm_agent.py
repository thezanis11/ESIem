"""Offline enrollment of a manifest-listed lab VM without printing/storing keys."""
import argparse
import json
from pathlib import Path
import shlex
import subprocess
import time

from vm_ssh import ROOT, connection


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=["gateway", "portal", "files", "student01", "staff01"])
    args = parser.parse_args()
    role = args.role
    compose = "cd /opt/campus-siem && sudo docker compose -p campussentinel -f runtime/soc/docker-compose.yml exec -T wazuh.manager "
    def manager(command):
        result = subprocess.run(connection("soc") + [compose + command], capture_output=True, text=True, timeout=45)
        if result.returncode:
            raise RuntimeError("Manager operation failed: " + result.stderr[-500:])
        return result.stdout
    keys = manager("cat /var/ossec/etc/client.keys")
    selected = next((line for line in keys.splitlines() if len(line.split()) == 4 and line.split()[1] == role), None)
    if selected is None:
        address = json.loads((ROOT / "config/assets.json").read_text())[role]["ip"]
        manager("/var/ossec/bin/manage_agents -a " + shlex.quote(address) + " -n " + shlex.quote(role))
        keys = manager("cat /var/ossec/etc/client.keys")
        selected = next(line for line in keys.splitlines() if len(line.split()) == 4 and line.split()[1] == role)
    agent_id = selected.split()[0]
    for group in (["linux", "gateway"] if role == "gateway" else ["linux"]):
        manager("/var/ossec/bin/agent_groups -a -i " + shlex.quote(agent_id) + " -g " + group + " -q")
    install_key = "sudo tee /var/ossec/etc/client.keys >/dev/null && sudo chown root:wazuh /var/ossec/etc/client.keys && sudo chmod 0640 /var/ossec/etc/client.keys && sudo systemctl enable wazuh-agent && sudo systemctl restart wazuh-agent"
    result = subprocess.run(connection(role) + [install_key], input=(selected + "\n").encode(), capture_output=True, timeout=180)
    if result.returncode:
        raise RuntimeError("Agent key import/start failed; no key printed")
    end = time.monotonic() + 100
    while time.monotonic() < end:
        status = manager("/var/ossec/bin/agent_control -i " + shlex.quote(agent_id))
        if "Status:     Active" in status:
            result = {"agent": role, "id": agent_id, "active": True, "manager_profile": "manager-only", "key_exposed": False}
            (ROOT / "reports" / ("local-vm-" + role + ".json")).write_text(json.dumps(result, indent=2))
            print(json.dumps(result))
            return
        time.sleep(4)
    raise RuntimeError("Agent did not become active; inspect private VM logs")


if __name__ == "__main__":
    main()
