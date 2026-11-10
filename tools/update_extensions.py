"""Upgrade only ESIem extensions in an existing generated 4.14.10 deployment.

Never regenerate credentials, certificates, agent keys or persistent volumes.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sys
import xml.etree.ElementTree as ET
import yaml

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--deployment", default="runtime/soc")
    args = parser.parse_args()
    target = Path(args.deployment).resolve()
    if json.loads((target / "PROVENANCE.json").read_text())["wazuh_version"] != "4.14.10":
        raise ValueError("Only generated Wazuh 4.14.10 deployments are supported")
    compose_file = target / "docker-compose.yml"
    compose = yaml.safe_load(compose_file.read_text())
    manager = compose["services"]["wazuh.manager"]
    if manager["image"] != "wazuh/wazuh-manager:4.14.10":
        raise ValueError("Unexpected manager image; refusing update")
    manager_file = target / "config/wazuh_cluster/wazuh_manager.conf"
    backup = target / "updates" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    backup.mkdir(parents=True, mode=0o700)
    shutil.copy2(compose_file, backup / compose_file.name)
    shutil.copy2(manager_file, backup / manager_file.name)
    for source in (ROOT / "wazuh/rules").glob("*.xml"):
        shutil.copy2(source, target / "config/campus/rules" / source.name)
    for group in (ROOT / "wazuh/groups").iterdir():
        shutil.copy2(group / "agent.conf", target / "config/campus/groups" / group.name / "agent.conf")
    script = target / "config/campus/fix-group-permissions.sh"
    shutil.copy2(ROOT / "infra/soc/fix-group-permissions.sh", script)
    volume = "./config/campus/fix-group-permissions.sh:/opt/esiem/fix-group-permissions.sh:ro"
    if volume not in manager["volumes"]:
        manager["volumes"].append(volume)
    hook = {"command": ["bash", "/opt/esiem/fix-group-permissions.sh"], "user": "root"}
    if hook not in manager.setdefault("post_start", []):
        manager["post_start"].append(hook)
    tree = ET.fromstring("<root>" + manager_file.read_text() + "</root>")
    auth = tree.find(".//auth")
    auth.find("disabled").text = "no"
    remote = auth.find("remote_enrollment")
    if remote is None:
        remote = ET.SubElement(auth, "remote_enrollment")
    remote.text = "no"
    manager_file.write_text("\n".join(ET.tostring(c, encoding="unicode") for c in tree))
    compose_file.write_text(yaml.safe_dump(compose, sort_keys=False))
    print(json.dumps({"updated": True, "credentials_rotated": False, "backup": str(backup),
                      "next": "Recreate only the manager service to load these extensions."}))


if __name__ == "__main__":
    main()
