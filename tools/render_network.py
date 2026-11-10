"""Produce Netplan files for VM console review. Never applies host networking."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    import yaml
    topology = json.loads((ROOT / "config/lab-topology.json").read_text())
    output = ROOT / "runtime/netplan"
    output.mkdir(parents=True, exist_ok=True)
    for name, machine in topology["machines"].items():
        interface = {"dhcp4": False, "dhcp6": False, "accept-ra": False, "addresses": [machine["ip"]],
                     "routes": [{"to": "default", "via": machine["gateway"]}]}
        config = {"network": {"version": 2, "ethernets": {machine["interface"]: interface}}}
        (output / (name + ".yaml")).write_text(yaml.safe_dump(config, sort_keys=False))
    interfaces = {}
    for name, network in topology["gateway"].items():
        interface = {"dhcp4": False, "dhcp6": False, "accept-ra": False, "addresses": [network["address"]]}
        if "gateway" in network:
            interface["routes"] = [{"to": "default", "via": network["gateway"]}]
        interfaces[network["interface"]] = interface
    (output / "gateway.yaml").write_text(yaml.safe_dump({"network": {"version": 2, "ethernets": interfaces}}, sort_keys=False))
    print(json.dumps({"generated_files": len(topology["machines"]) + 1, "output": str(output), "applied": False}))


if __name__ == "__main__":
    main()
