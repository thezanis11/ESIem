"""Render an isolated deployment from pinned, hash-verified upstream files."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def prepare(output, manager_bind="127.0.0.1"):
    import bcrypt
    import yaml
    import ipaddress
    ipaddress.IPv4Address(manager_bind)
    destination = Path(output).resolve()
    if destination.exists():
        raise ValueError("Destination already exists: refusing to rotate secrets or overwrite a deployment")
    upstream = ROOT / "vendor/wazuh-docker"
    manifest = json.loads((upstream / "MANIFEST.json").read_text())
    for name, entry in manifest.items():
        if hashlib.sha256((upstream / name).read_bytes()).hexdigest() != entry["sha256"]:
            raise ValueError("Upstream checksum mismatch: " + name)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(upstream / "single-node", destination)
    if os.name != "nt":
        destination.chmod(0o700)
    passwords = {name: "Cs!" + secrets.token_urlsafe(24) + "9a" for name in ("admin", "dashboard", "api", "enrollment")}
    passwords["cluster_key"] = secrets.token_hex(16)
    secret_file = destination / "credentials.json"
    secret_file.write_text(json.dumps(passwords, indent=2) + "\n", encoding="utf-8")
    if os.name != "nt":
        secret_file.chmod(0o600)
    compose_file = destination / "docker-compose.yml"
    compose = yaml.safe_load(compose_file.read_text())
    services = compose["services"]
    for name, service in services.items():
        if "environment" in service:
            service["environment"] = {item.partition("=")[0]: item.partition("=")[2].strip('"') for item in service["environment"]}
        service["logging"] = {"driver": "json-file", "options": {"max-size": "10m", "max-file": "3"}}
        service["networks"] = ["soc"]
    manager, indexer, dashboard = (services[n] for n in ("wazuh.manager", "wazuh.indexer", "wazuh.dashboard"))
    manager["ports"] = [f"{manager_bind}:1514:1514", "127.0.0.1:55000:55000"]
    indexer.pop("ports", None)
    dashboard["ports"] = ["127.0.0.1:8443:5601"]
    for component in (manager, dashboard):
        component["environment"]["INDEXER_PASSWORD"] = passwords["admin"]
        component["environment"]["API_PASSWORD"] = passwords["api"]
    dashboard["environment"]["DASHBOARD_PASSWORD"] = passwords["dashboard"]
    permissions = destination / "config/campus/fix-group-permissions.sh"
    permissions.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / "infra/soc/fix-group-permissions.sh", permissions)
    manager["volumes"].append("./config/campus/fix-group-permissions.sh:/opt/esiem/fix-group-permissions.sh:ro")
    manager["post_start"] = [{"command": ["bash", "/opt/esiem/fix-group-permissions.sh"], "user": "root"}]
    for source in (ROOT / "wazuh/rules").glob("*.xml"):
        target = destination / "config/campus/rules" / source.name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        manager["volumes"].append(f"./config/campus/rules/{source.name}:/wazuh-config-mount/etc/rules/{source.name}:ro")
    for group in (ROOT / "wazuh/groups").iterdir():
        target = destination / "config/campus/groups" / group.name
        shutil.copytree(group, target)
        manager["volumes"].append(f"./config/campus/groups/{group.name}/agent.conf:/wazuh-config-mount/etc/shared/{group.name}/agent.conf:ro")
    compose["networks"] = {"soc": {"driver": "bridge"}}
    compose_file.write_text(yaml.safe_dump(compose, sort_keys=False), encoding="utf-8")
    users_file = destination / "config/wazuh_indexer/internal_users.yml"
    users = {"_meta": {"type": "internalusers", "config_version": 2}}
    for name, secret_name in (("admin", "admin"), ("kibanaserver", "dashboard")):
        users[name] = {"hash": bcrypt.hashpw(passwords[secret_name].encode(), bcrypt.gensalt(rounds=12)).decode(), "reserved": True}
    users["admin"]["backend_roles"] = ["admin"]
    users_file.write_text(yaml.safe_dump(users, sort_keys=False), encoding="utf-8")
    api_file = destination / "config/wazuh_dashboard/wazuh.yml"
    api_config = yaml.safe_load(api_file.read_text())
    next(iter(api_config["hosts"][0].values()))["password"] = passwords["api"]
    api_file.write_text(yaml.safe_dump(api_config, sort_keys=False), encoding="utf-8")
    manager_file = destination / "config/wazuh_cluster/wazuh_manager.conf"
    tree = ET.fromstring("<root>" + manager_file.read_text() + "</root>")
    # Keep the local registration socket alive so keys and Wazuh DB stay in sync.
    # Disable only the remote TCP enrollment listener, not the whole daemon.
    auth = tree.find(".//auth")
    auth.find("disabled").text = "no"
    ET.SubElement(auth, "remote_enrollment").text = "no"
    tree.find(".//auth/use_password").text = "yes"
    tree.find(".//cluster/key").text = passwords["cluster_key"]
    # Keep vulnerability feeds optional until egress and capacity have been approved.
    tree.find(".//vulnerability-detection/enabled").text = "no"
    manager_file.write_text("\n".join(ET.tostring(child, encoding="unicode") for child in tree), encoding="utf-8")
    index_config = destination / "config/wazuh_indexer/wazuh.indexer.yml"
    index_settings = yaml.safe_load(index_config.read_text())
    index_settings["cluster.routing.allocation.disk.threshold_enabled"] = True
    index_settings["plugins.security.ssl.transport.enforce_hostname_verification"] = True
    index_config.write_text(yaml.safe_dump(index_settings, sort_keys=False), encoding="utf-8")
    (destination / "PROVENANCE.json").write_text(json.dumps({"wazuh_version": "4.14.10", "upstream_manifest": manifest,
        "manager_bind": manager_bind, "generated_secrets": True, "integration_validated": False}, indent=2) + "\n")
    return {"deployment": str(destination), "dashboard": "https://localhost:8443", "credentials_file": str(secret_file),
            "next": "Generate certificates, validate Compose, then start on the dedicated Linux SOC host."}
