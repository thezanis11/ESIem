"""Create new, powered-off VirtualBox lab VMs. Never alter existing machines.

No ISO download, VM startup, bridged adapter or shared host folder is performed.
On failure, preserve created objects and a progress manifest for inspection.
"""
import argparse
import copy
import json
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def plan(storage):
    topology = json.loads((ROOT / "config/lab-topology.json").read_text())
    machines = []
    zones = {"soc": "management", "admin": "management", "student01": "students",
             "staff01": "staff", "portal": "dmz", "files": "servers"}
    for i, (role, spec) in enumerate(topology["machines"].items(), 1):
        machines.append({"name": "ESIem-" + role, "role": role, "cpus": spec["vcpus"],
                         "ram_MiB": spec["ram_GiB"] * 1024, "disk_GB": spec["disk_GB"],
                         "adapters": [{"slot": 1, "zone": zones[role], "mac": f"02007710{i:04X}"}]})
    adapters = [{"slot": i, "zone": zone, "mac": f"02007700{i:04X}"}
                for i, zone in enumerate(topology["gateway"], 1)]
    machines.append({"name": "ESIem-gateway", "role": "gateway", "cpus": 2, "ram_MiB": 2048,
                     "disk_GB": 16, "adapters": adapters})
    return {"name": "ESIem", "storage": str(Path(storage).resolve()), "machines": machines,
            "starts_machines": False, "bridged_adapters": False, "guest_os_installed": False,
            "note": "Full lab requires more memory than the current PC can safely allocate simultaneously."}


def run(vbox, *arguments, timeout=90):
    result = subprocess.run([str(vbox), *map(str, arguments)], capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return result.stdout


def create(specification, vbox):
    storage = Path(specification["storage"])
    existing = set(re.findall(r'^"([^"]+)"', run(vbox, "list", "vms"), flags=re.MULTILINE))
    conflicts = existing.intersection(machine["name"] for machine in specification["machines"])
    if conflicts:
        raise ValueError("Existing VM names; refusing to modify them: " + ", ".join(sorted(conflicts)))
    if storage.exists() and any(storage.iterdir()):
        raise ValueError("Storage directory is not empty; refusing to overwrite it")
    if shutil.disk_usage(storage.anchor).free < 180_000_000_000:
        raise ValueError("At least 180 GB free physical storage required for the full lab budget")
    storage.mkdir(parents=True, exist_ok=True)
    progress = {"plan": specification, "created": [], "complete": False}
    manifest = storage / "ESIem-lab.json"
    manifest.write_text(json.dumps(progress, indent=2), encoding="utf-8")
    for machine in specification["machines"]:
        name = machine["name"]
        run(vbox, "createvm", "--name", name, "--platform-architecture", "x86", "--ostype", "Ubuntu_64",
            "--basefolder", storage, "--groups", "/ESIem", "--register")
        progress["created"].append({"name": name, "state": "registered"})
        manifest.write_text(json.dumps(progress, indent=2), encoding="utf-8")
        run(vbox, "modifyvm", name, "--memory", machine["ram_MiB"], "--cpus", machine["cpus"],
            "--chipset", "ich9", "--ioapic", "on", "--graphicscontroller", "vmsvga", "--vram", "16",
            "--audio-enabled", "off", "--clipboard-mode", "disabled", "--drag-and-drop", "disabled",
            "--boot1", "dvd", "--boot2", "disk", "--boot3", "none", "--boot4", "none")
        for adapter in machine["adapters"]:
            slot = adapter["slot"]
            run(vbox, "modifyvm", name, f"--nic{slot}", "intnet", f"--intnet{slot}", "ESIem-" + adapter["zone"],
                f"--mac-address{slot}", adapter["mac"], f"--nic-type{slot}", "82540EM", f"--cable-connected{slot}", "on")
        disk = storage / name / (name + ".vdi")
        run(vbox, "createmedium", "disk", "--filename", disk, "--size", machine["disk_GB"] * 1024,
            "--format", "VDI", "--variant", "Standard")
        run(vbox, "storagectl", name, "--name", "SATA", "--add", "sata", "--controller", "IntelAhci", "--portcount", "2")
        run(vbox, "storageattach", name, "--storagectl", "SATA", "--port", "0", "--device", "0", "--type", "hdd", "--medium", disk)
        run(vbox, "storageattach", name, "--storagectl", "SATA", "--port", "1", "--device", "0", "--type", "dvddrive", "--medium", "emptydrive")
        progress["created"][-1]["state"] = "configured_powered_off"
        manifest.write_text(json.dumps(progress, indent=2), encoding="utf-8")
        print(name + ": configured, powered off", flush=True)
    topology = json.loads((ROOT / "config/lab-topology.json").read_text())
    for machine in specification["machines"]:
        if machine["role"] == "gateway":
            for adapter in machine["adapters"]:
                topology["gateway"][adapter["zone"]]["mac"] = adapter["mac"]
        else:
            topology["machines"][machine["role"]]["mac"] = machine["adapters"][0]["mac"]
    runtime = ROOT / "runtime"
    runtime.mkdir(exist_ok=True)
    (runtime / "virtualbox-topology.json").write_text(json.dumps(topology, indent=2), encoding="utf-8")
    progress["complete"] = True
    manifest.write_text(json.dumps(progress, indent=2), encoding="utf-8")
    return progress


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--storage", required=True)
    parser.add_argument("--vbox", default=r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe")
    parser.add_argument("--create", action="store_true", help="Create powered-off VM shells; default is plan only")
    args = parser.parse_args()
    specification = plan(args.storage)
    if args.create:
        create(specification, args.vbox)
    else:
        print(json.dumps(specification, indent=2))


if __name__ == "__main__":
    main()
