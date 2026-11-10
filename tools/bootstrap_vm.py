"""Controlled first boot of one new ESIem VM with temporary localhost-only SSH.

Only the explicit lab manifest and powered-off lab machines may be changed.
Always retains at least 2 GiB currently available host RAM before starting.
"""
import argparse
import ctypes
import io
import json
from pathlib import Path
import time

import pycdlib
import yaml
from virtualbox_lab import ROOT, run
from seed_virtualbox import make_iso


def available_memory_mib():
    class Memory(ctypes.Structure):
        _fields_ = [("length", ctypes.c_ulong), ("load", ctypes.c_ulong)] + [
            (name, ctypes.c_ulonglong) for name in ("total", "available", "page", "page_available", "virtual", "virtual_available", "extended")]
    state = Memory()
    state.length = ctypes.sizeof(state)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(state)):
        raise OSError("Cannot inspect available host memory")
    return state.available // 1024**2


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("role")
    parser.add_argument("--storage", default="G:/ESIem-lab")
    parser.add_argument("--vbox", default=r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe")
    parser.add_argument("--memory-mib", type=int)
    parser.add_argument("--start", action="store_true")
    args = parser.parse_args()
    storage = Path(args.storage).resolve()
    manifest = json.loads((storage / "ESIem-lab.json").read_text())
    index, machine = next((i, m) for i, m in enumerate(manifest["plan"]["machines"], 1) if m["role"] == args.role)
    name = machine["name"]
    if not manifest.get("ubuntu_prepared", {}).get(name):
        raise ValueError("Ubuntu disk not yet prepared")
    details = run(args.vbox, "showvminfo", name, "--machinereadable")
    config = Path(next(line for line in details.splitlines() if line.startswith("CfgFile=")).partition("=")[2].strip('"').replace("\\\\", "\\")).resolve()
    if config.parent not in {(storage / name).resolve(), (storage / "ESIem" / name).resolve()}:
        raise ValueError("VM configuration is outside the exact lab paths")
    if 'VMState="poweroff"' not in details:
        raise ValueError("VM must be powered off for first-boot preparation")
    seed = storage / name / "ESIem-seed.iso"
    iso = pycdlib.PyCdlib()
    iso.open(str(seed))
    files = {}
    for filename in ("user-data", "meta-data", "network-config"):
        output = io.BytesIO()
        iso.get_file_from_iso_fp(output, rr_path="/" + filename)
        files[filename] = output.getvalue().decode()
    iso.close()
    network = yaml.safe_load(files["network-config"])
    mac = f"02007790{index:04X}"
    network["ethernets"]["bootstrap0"] = {"match": {"macaddress": ":".join(mac[i:i+2] for i in range(0, 12, 2)).lower()},
        "set-name": "bootstrap0", "dhcp4": True, "dhcp6": False, "accept-ra": False,
        "dhcp4-overrides": {"route-metric": 50}}
    # Route campus addresses through the lab gateway even while NAT is present.
    for key, interface in network["ethernets"].items():
        if key == "bootstrap0":
            continue
        for route in interface.get("routes", []):
            if route["to"] == "default":
                route["metric"] = 500
                if args.role != "gateway":
                    campus_route = {"to": "10.77.0.0/16", "via": route["via"]}
                    if campus_route not in interface["routes"]:
                        interface["routes"].append(campus_route)
                break
    files["network-config"] = yaml.safe_dump(network, sort_keys=False)
    # Detach optical medium before updating it, never an operating system disk.
    run(args.vbox, "storageattach", name, "--storagectl", "SATA", "--port", "1", "--device", "0", "--type", "dvddrive", "--medium", "emptydrive")
    make_iso(seed, files)
    run(args.vbox, "storageattach", name, "--storagectl", "SATA", "--port", "1", "--device", "0", "--type", "dvddrive", "--medium", seed)
    slot = 7 if args.role == "gateway" else 2
    port = 22010 + index
    run(args.vbox, "modifyvm", name, f"--nic{slot}", "nat", f"--mac-address{slot}", mac,
        f"--nic-type{slot}", "82540EM", f"--cable-connected{slot}", "on")
    if "ESIem-bootstrap-ssh" not in details:
        run(args.vbox, "modifyvm", name, f"--nat-pf{slot}", f"ESIem-bootstrap-ssh,tcp,127.0.0.1,{port},,22")
    run(args.vbox, "modifyvm", name, "--uart1", "0x3F8", "4", "--uart-mode1", "file", str(storage / name / "serial.log"))
    memory = args.memory_mib or machine["ram_MiB"]
    if memory < 768 or memory > machine["ram_MiB"]:
        raise ValueError("Memory must be between 768 MiB and this VM's planned allocation")
    run(args.vbox, "modifyvm", name, "--memory", memory)
    status = {"name": name, "role": args.role, "ssh_local_port": port, "temporary_nat_slot": slot,
              "memory_MiB": memory, "host_available_MiB": available_memory_mib(), "started": False}
    if args.start:
        if status["host_available_MiB"] < memory + 2048:
            raise ValueError(f"Host memory guard: {status['host_available_MiB']} MiB available, need {memory+2048} MiB")
        run(args.vbox, "startvm", name, "--type", "headless", timeout=120)
        status["started"] = True
    output = ROOT / "runtime/vm-access" / (args.role + "-bootstrap.json")
    output.write_text(json.dumps(status, indent=2))
    print(json.dumps(status))


if __name__ == "__main__":
    main()
