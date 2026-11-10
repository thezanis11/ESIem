"""Optional gateway-local Wazuh active response. Simulation is the default.

No shell execution, no account disabling, no changes outside the dedicated lab set.
An expiring nftables set enforces rollback independently of this process.
"""
import ipaddress
import json
import os
from pathlib import Path
import stat
import subprocess
import sys


def plan(alert, policy):
    rule = str(alert.get("rule", {}).get("id", ""))
    if rule not in policy["allowed_rule_ids"]:
        raise ValueError("Rule is not authorized for temporary isolation")
    data = alert.get("data", {})
    address = ipaddress.ip_address(data.get("srcip", data.get("src_ip", "")))
    if address.version != 4 or str(address) in policy["protected_addresses"]:
        raise ValueError("Protected or unsupported address")
    networks = [ipaddress.ip_network(n) for n in policy["allowed_subnets"]]
    if not any(address in network and address not in (network.network_address, network.broadcast_address) for network in networks):
        raise ValueError("Address is outside the authorized lab endpoint ranges")
    if policy["timeout_seconds"] != 300:
        raise ValueError("Only a five-minute isolation lease is implemented")
    return {"address": str(address), "ttl_seconds": 300, "mode": "execute" if policy["execute"] else "dry-run"}


def main():
    path = Path("/etc/campus/response-policy.json")
    policy = json.loads(path.read_text())
    if policy["execute"]:
        status = path.stat()
        if os.geteuid() != 0 or status.st_uid != 0 or status.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise PermissionError("Execution policy must be root-owned and not writable by group or others")
    raw = sys.stdin.readline(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError("Oversized active-response message")
    message = json.loads(raw)
    if message["command"] != "add":
        return  # Kernel timeout handles expiry; command is stateless.
    proposal = plan(message["parameters"]["alert"], policy)
    if policy["execute"]:
        # Address is parsed and the set name and timeout are constants.
        command = ["/usr/sbin/nft", "add", "element", "inet", "campus", "quarantine_v4",
                   "{", proposal["address"], "timeout", "300s", "}"]
        subprocess.run(command, check=True, timeout=5, capture_output=True)
    with open("/var/ossec/logs/active-responses.log", "a", encoding="utf-8") as log:
        log.write(json.dumps({"campus_response": proposal}, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
