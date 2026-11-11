"""Build an offline incident view exclusively from completed native CI evidence."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from campus.report import write_report


def main():
    stack = json.loads((ROOT / "reports/stack-acceptance.json").read_text())
    network = json.loads((ROOT / "reports/network-acceptance.json").read_text())
    live = json.loads((ROOT / "reports/live-correlation.json").read_text())
    for report in (stack, network):
        if not report["completed"] or not all(t["passed"] for t in report["tests"]):
            raise ValueError("Cannot label an incomplete or failing acceptance run as validated")
    target = ROOT / "reports/validated-incidents.html"
    write_report(live["incidents"], live["audit"], target)
    banner = ('<p class="tag">RECETTE NATIVE VALIDÉE : ' + str(len(stack["tests"])) + ' CONTRÔLES SIEM · '
              + str(len(network["tests"])) + ' CONTRÔLES RÉSEAU</p>'
              '<p>Campagne de laboratoire : véritables services Wazuh et agent, lignes SSH de test, '
              'modification réelle de fichier et rejeu de captures EVE issues de marqueurs HTTP inoffensifs. '
              'Ces incidents ne décrivent pas des attaques sur une université.</p>')
    document = target.read_text(encoding="utf-8").replace("<h1>ESIem</h1>", "<h1>ESIem</h1>" + banner)
    target.write_bytes(document.encode())
    print(json.dumps({"report": str(target), "incidents": len(live["incidents"]), "native_checks": len(stack["tests"]), "network_checks": len(network["tests"])}))


if __name__ == "__main__":
    main()
