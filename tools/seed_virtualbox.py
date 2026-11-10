"""Prepare Ubuntu OS disks and NoCloud seed ISOs, never start VMs.

Only the explicitly created ESIem VM shells in the lab manifest are accepted.
Private SSH keys and console passwords stay in ignored local runtime storage.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

import pycdlib
import yaml

from virtualbox_lab import ROOT, run


def make_iso(path, files):
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, joliet=3, rock_ridge="1.09", vol_ident="cidata")
    streams = []
    for index, (name, content) in enumerate(files.items(), 1):
        stream = io.BytesIO(content.encode())
        streams.append(stream)
        iso.add_fp(stream, len(content.encode()), iso_path=f"/FILE{index:02d}.;1", rr_name=name, joliet_path="/" + name)
    iso.write(str(path))
    iso.close()


def password_hash(password):
    command = ["openssl", "passwd", "-6", "-stdin"]
    if os.name == "nt":
        native = Path(r"C:\Program Files\Git\usr\bin\openssl.exe")
        command = [str(native), *command[1:]] if native.exists() else ["wsl", "-d", "Ubuntu", "--", *command]
    result = subprocess.run(command, input=password + "\n", text=True, capture_output=True, check=True, timeout=30)
    result = result.stdout.strip()
    if not result.startswith("$6$"):
        raise ValueError("Expected SHA-512 crypt console password hash")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--storage", required=True)
    parser.add_argument("--vbox", default=r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe")
    args = parser.parse_args()
    storage = Path(args.storage).resolve()
    manifest_file = storage / "ESIem-lab.json"
    progress = json.loads(manifest_file.read_text())
    if not progress["complete"] or Path(progress["plan"]["storage"]).resolve() != storage:
        raise ValueError("The completed lab manifest must match the exact storage path")
    image = storage / "images/ubuntu-24.04-server-cloudimg-amd64.vmdk"
    provenance = json.loads((storage / "images/ubuntu-image.json").read_text())
    with image.open("rb") as source:
        actual_hash = hashlib.file_digest(source, "sha256").hexdigest()
    if actual_hash != provenance["sha256"]:
        raise ValueError("Ubuntu image checksum mismatch")
    private = ROOT / "runtime/vm-access"
    private.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        private.chmod(0o700)
    credentials_file = private / "console-credentials.json"
    credentials = json.loads(credentials_file.read_text()) if credentials_file.exists() else {}
    key = private / "id_ed25519"
    if not key.exists():
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "ESIem-lab-only", "-f", str(key)], check=True)
    public_key = key.with_suffix(".pub").read_text().strip()
    topology = json.loads((ROOT / "runtime/virtualbox-topology.json").read_text())
    networking = ROOT / "runtime/netplan"
    # Use only tracked project files. No private runtime contents or local caches.
    names = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT, text=True).split("\0")
    project_files = []
    for name in names:
        if not name or name.startswith((".github/", "reports/")):
            continue
        import base64
        project_files.append({"path": "/opt/campus-siem/" + name, "owner": "root:root", "permissions": "0644",
                              "encoding": "b64", "content": base64.b64encode((ROOT / name).read_bytes()).decode()})
    for machine in progress["plan"]["machines"]:
        role, name = machine["role"], machine["name"]
        if progress.get("ubuntu_prepared", {}).get(name):
            print(name + ": Ubuntu disk already prepared; preserved", flush=True)
            continue
        details = run(args.vbox, "showvminfo", name, "--machinereadable")
        config_line = next(line for line in details.splitlines() if line.startswith("CfgFile="))
        registered_config = Path(config_line.partition("=")[2].strip('"').replace("\\\\", "\\")).resolve()
        allowed_parents = {(storage / name).resolve(), (storage / "ESIem" / name).resolve()}
        if registered_config.parent not in allowed_parents or 'VMState="poweroff"' not in details:
            raise ValueError("Refusing to change a VM outside the lab directory or not powered off")
        password = credentials.setdefault(name, "Es!" + secrets.token_urlsafe(20) + "8a")
        credentials_file.write_text(json.dumps(credentials, indent=2), encoding="utf-8")
        if os.name != "nt":
            credentials_file.chmod(0o600)
        cloud = {"hostname": role, "preserve_hostname": False, "manage_etc_hosts": True,
                 "disable_root": True, "ssh_pwauth": False,
                 "users": [{"name": "labadmin", "shell": "/bin/bash", "groups": ["adm", "sudo"],
                            "sudo": ["ALL=(ALL) NOPASSWD:ALL"], "lock_passwd": False,
                            "hashed_passwd": password_hash(password), "ssh_authorized_keys": [public_key]}],
                 "growpart": {"mode": "auto", "devices": ["/"]}, "resize_rootfs": True,
                 "write_files": project_files,
                 "runcmd": [["mkdir", "-p", "/opt/campus-siem/runtime"], ["chmod", "0700", "/opt/campus-siem/runtime"]]}
        network = yaml.safe_load((networking / (role + ".yaml")).read_text())["network"]
        seed = storage / name / "ESIem-seed.iso"
        make_iso(seed, {"user-data": "#cloud-config\n" + yaml.safe_dump(cloud, sort_keys=False),
                        "meta-data": yaml.safe_dump({"instance-id": "ESIem-" + role + "-v1", "local-hostname": role}),
                        "network-config": yaml.safe_dump(network, sort_keys=False)})
        os_disk = storage / name / (name + "-ubuntu.vdi")
        if not os_disk.exists():
            # Convert the stream-optimized VMDK only once. Reopening its zero UUID
            # can conflict with VirtualBox's generated media-registry UUID.
            base_disk = storage / "images/ubuntu-base.vdi"
            source = base_disk if base_disk.exists() else image
            run(args.vbox, "clonemedium", "disk", source, os_disk, "--format", "VDI", timeout=900)
            requested = max(machine["disk_GB"], 16 if base_disk.exists() else 0)
            run(args.vbox, "modifymedium", "disk", os_disk, "--resize", requested * 1024)
        run(args.vbox, "storageattach", name, "--storagectl", "SATA", "--port", "0", "--device", "0", "--type", "hdd", "--medium", os_disk)
        run(args.vbox, "storageattach", name, "--storagectl", "SATA", "--port", "1", "--device", "0", "--type", "dvddrive", "--medium", seed)
        run(args.vbox, "modifyvm", name, "--firmware", "efi", "--boot1", "disk", "--boot2", "dvd")
        progress.setdefault("ubuntu_prepared", {})[name] = {"sha256": actual_hash, "started": False,
            "guest_first_boot_completed": False, "project_sources_copied_to_seed": len(project_files)}
        manifest_file.write_text(json.dumps(progress, indent=2), encoding="utf-8")
        print(name + ": Ubuntu disk and initialization ISO attached; VM remains powered off", flush=True)
    print("Private lab access data retained in ignored runtime/vm-access; no passwords printed.")


if __name__ == "__main__":
    main()
