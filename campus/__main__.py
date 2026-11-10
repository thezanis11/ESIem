import argparse
import json
from pathlib import Path
import platform
import shutil
import sys

from .engine import Engine

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description="Campus Sentinel — Wazuh university lab")
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare", help="Generate a fresh Wazuh deployment, never overwrite secrets")
    prepare.add_argument("--output", default="runtime/soc")
    prepare.add_argument("--manager-bind", default="127.0.0.1")
    ingest = commands.add_parser("ingest", help="Read a Wazuh alerts.json snapshot or stdin; duplicates are ignored")
    ingest.add_argument("input", help="Path to alerts.json, or - for stdin")
    ingest.add_argument("--db", default="runtime/incidents.db")
    ingest.add_argument("--assets", default=str(ROOT / "config/assets.json"))
    for command in ("report", "audit"):
        sub = commands.add_parser(command)
        sub.add_argument("--db", default="runtime/incidents.db")
        sub.add_argument("--assets", default=str(ROOT / "config/assets.json"))
        if command == "report":
            sub.add_argument("--output", default="runtime/report.html")
    commands.add_parser("preflight", help="Read-only resource and tool inventory; no downloads")
    args = parser.parse_args()
    if args.command == "prepare":
        from .deploy import prepare
        print(json.dumps(prepare(args.output, args.manager_bind), indent=2))
        return
    if args.command == "preflight":
        print(json.dumps({"os": platform.platform(), "python": platform.python_version(),
                          "disk_free_GiB": round(shutil.disk_usage('.').free / 2**30, 2),
                          "docker_client": bool(shutil.which("docker")),
                          "soc_minimum": {"cores": 4, "RAM_GiB": 8, "disk_GB": 50},
                          "note": "Inspect physical host space too: thin-provisioned VM capacity is not free physical storage."}, indent=2))
        return
    Path(args.db).parent.mkdir(parents=True, exist_ok=True)
    engine = Engine(args.db, json.loads(Path(args.assets).read_text()))
    try:
        if args.command == "ingest":
            handle = sys.stdin if args.input == "-" else open(args.input, encoding="utf-8")
            accepted = duplicates = 0
            try:
                for line_number, line in enumerate(handle, 1):
                    if not line.strip():
                        continue
                    try:
                        if len(line) > 1024 * 1024:
                            raise ValueError("Event exceeds the 1 MiB input limit")
                        if engine.ingest(json.loads(line)):
                            accepted += 1
                        else:
                            duplicates += 1
                    except (ValueError, KeyError, TypeError) as error:
                        raise ValueError(f"Input line {line_number}: {error}") from error
            finally:
                if handle is not sys.stdin:
                    handle.close()
            print(json.dumps({"accepted": accepted, "duplicates": duplicates, "incidents": len(engine.incidents())}))
        elif args.command == "report":
            from .report import write_report
            audit = engine.verify_audit()
            write_report(engine.incidents(), audit, args.output)
            print(json.dumps({"report": str(Path(args.output).resolve()), "incidents": len(engine.incidents())}))
        else:
            print(json.dumps(engine.verify_audit(), indent=2))
    finally:
        engine.close()


if __name__ == "__main__":
    main()
