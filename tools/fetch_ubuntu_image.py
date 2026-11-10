"""Fetch the official Ubuntu cloud disk to external lab storage, with SHA-256.

The checksum comes from Ubuntu over HTTPS; this does not claim GPG verification.
"""
import argparse
import hashlib
import json
from pathlib import Path
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--storage", required=True)
    args = parser.parse_args()
    storage = Path(args.storage).resolve()
    manifest = json.loads((storage / "ESIem-lab.json").read_text())
    if Path(manifest["plan"]["storage"]).resolve() != storage:
        raise ValueError("Storage does not match the lab manifest")
    folder = storage / "images"
    folder.mkdir(exist_ok=True)
    base = "https://cloud-images.ubuntu.com/releases/noble/release/"
    name = "ubuntu-24.04-server-cloudimg-amd64.vmdk"
    final = folder / name
    if final.exists():
        raise ValueError("Image exists; refusing overwrite")
    with urllib.request.urlopen(base + "SHA256SUMS", timeout=30) as response:
        sums = response.read().decode()
    expected = next(line.split()[0] for line in sums.splitlines() if line.split()[-1].lstrip("*") == name)
    (folder / "SHA256SUMS").write_bytes(sums.encode())
    temporary = folder / (name + ".part")
    if temporary.exists():
        raise ValueError("A partial download exists; inspect it before retrying")
    hashed = hashlib.sha256()
    total = 0
    with urllib.request.urlopen(base + name, timeout=60) as source, temporary.open("xb") as target:
        while chunk := source.read(4 * 1024 * 1024):
            target.write(chunk)
            hashed.update(chunk)
            total += len(chunk)
    if hashed.hexdigest() != expected:
        raise ValueError("Checksum mismatch; partial image retained and not used")
    temporary.rename(final)
    (folder / "ubuntu-image.json").write_text(json.dumps({"url": base + name, "sha256": expected,
        "bytes": total, "checksum_verified": True, "gpg_signature_verified": False}, indent=2))
    print(json.dumps({"bytes": total, "checksum_verified": True}))


if __name__ == "__main__":
    main()
