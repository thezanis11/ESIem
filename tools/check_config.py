"""Structural checks supplement, never replace, native Wazuh/Suricata validation."""
import hashlib
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def main():
    ids = []
    for path in (ROOT / "wazuh").rglob("*.xml"):
        tree = ET.fromstring("<root>" + path.read_text() + "</root>")
        for rule in tree.findall(".//rule"):
            value = int(rule.attrib["id"])
            assert 110000 <= value < 110100, path
            ids.append(value)
    assert len(ids) == len(set(ids)), "Duplicate custom rule IDs"
    for path in (ROOT / "wazuh/groups").rglob("agent.conf"):
        ET.fromstring(path.read_text())
    upstream = ROOT / "vendor/wazuh-docker"
    manifest = json.loads((upstream / "MANIFEST.json").read_text())
    for name, item in manifest.items():
        assert hashlib.sha256((upstream / name).read_bytes()).hexdigest() == item["sha256"], name
    print(json.dumps({"custom_rule_ids": ids, "verified_upstream_files": len(manifest), "native_validation": "separate integration step"}))


if __name__ == "__main__":
    main()
