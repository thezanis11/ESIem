import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("virtualbox_lab", ROOT / "tools/virtualbox_lab.py")
virtualbox = importlib.util.module_from_spec(spec)
spec.loader.exec_module(virtualbox)


class VirtualBoxTests(unittest.TestCase):
    def test_no_existing_vm_is_modified(self):
        specification = virtualbox.plan(ROOT / ".cache/test-vm-storage")
        with patch.object(virtualbox, "run", return_value='"ESIem-soc" {some-uuid}\n') as command:
            with self.assertRaisesRegex(ValueError, "Existing VM"):
                virtualbox.create(specification, "VBoxManage")
            command.assert_called_once_with("VBoxManage", "list", "vms")

    def test_networks_are_internal_and_macs_unique(self):
        specification = virtualbox.plan(ROOT / ".cache/test-vm-storage")
        adapters = [a for machine in specification["machines"] for a in machine["adapters"]]
        self.assertEqual(len(adapters), len({a["mac"] for a in adapters}))
        self.assertFalse(specification["starts_machines"])
        self.assertFalse(specification["bridged_adapters"])
        self.assertEqual(7, len(specification["machines"]))
        gateway = next(m for m in specification["machines"] if m["role"] == "gateway")
        self.assertEqual(6, len(gateway["adapters"]))
