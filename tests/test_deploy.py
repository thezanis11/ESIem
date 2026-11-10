import json
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
(ROOT / ".cache").mkdir(exist_ok=True)

try:
    import bcrypt
    import yaml
    DEPENDENCIES = True
except ImportError:
    DEPENDENCIES = False


@unittest.skipUnless(DEPENDENCIES, "Install requirements.txt for deployment checks")
class DeploymentTests(unittest.TestCase):
    def test_generated_stack_uses_unique_credentials_and_restricted_ports(self):
        from campus.deploy import prepare
        with tempfile.TemporaryDirectory(dir=ROOT / ".cache") as temporary:
            folder = Path(temporary) / "soc"
            prepare(folder, "10.77.10.10")
            compose = yaml.safe_load((folder / "docker-compose.yml").read_text())
            services = compose["services"]
            self.assertNotIn("ports", services["wazuh.indexer"])
            self.assertEqual(["127.0.0.1:8443:5601"], services["wazuh.dashboard"]["ports"])
            self.assertNotIn("1515", str(services["wazuh.manager"]["ports"]))
            credentials = json.loads((folder / "credentials.json").read_text())
            self.assertEqual(len(credentials), len(set(credentials.values())))
            users = yaml.safe_load((folder / "config/wazuh_indexer/internal_users.yml").read_text())
            self.assertEqual({"_meta", "admin", "kibanaserver"}, set(users))
            self.assertTrue(bcrypt.checkpw(credentials["admin"].encode(), users["admin"]["hash"].encode()))
            api = yaml.safe_load((folder / "config/wazuh_dashboard/wazuh.yml").read_text())
            self.assertEqual(credentials["api"], next(iter(api["hosts"][0].values()))["password"])
            config = ET.fromstring("<root>" + (folder / "config/wazuh_cluster/wazuh_manager.conf").read_text() + "</root>")
            self.assertEqual("no", config.find(".//auth/disabled").text)
            self.assertEqual("no", config.find(".//auth/remote_enrollment").text)
            self.assertNotIn("SecretPassword", (folder / "docker-compose.yml").read_text())
            with self.assertRaisesRegex(ValueError, "already exists"):
                prepare(folder)

    def test_manager_bind_must_be_an_ipv4_address(self):
        from campus.deploy import prepare
        with self.assertRaises(ValueError):
            prepare(ROOT / ".cache/never-created", "0.0.0.0; echo unsafe")
