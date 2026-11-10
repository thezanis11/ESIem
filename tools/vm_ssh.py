"""Noninteractive SSH to one ESIem bootstrap port; dedicated host-key database."""
import argparse
import json
from pathlib import Path
import subprocess
import shlex

ROOT = Path(__file__).resolve().parents[1]


def connection(role):
    private = ROOT / "runtime/vm-access"
    status = json.loads((private / (role + "-bootstrap.json")).read_text())
    return ["ssh", "-i", str(private / "id_ed25519"), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
            "-o", "UserKnownHostsFile=" + str(private / "known_hosts"), "-o", "ConnectTimeout=10",
            "-p", str(status["ssh_local_port"]), "labadmin@127.0.0.1"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("role")
    parser.add_argument("--script")
    parser.add_argument("--command")
    args = parser.parse_args()
    if bool(args.script) == bool(args.command):
        parser.error("Choose a script or command")
    # Read the complete script before executing it, with child stdin closed.
    # Otherwise docker/apt may consume subsequent bash script lines as input.
    # Mirror the script at its project-relative guest path. Executing a real file
    # preserves $0/BASH_SOURCE for installers that resolve sibling config files.
    if args.script:
        relative = Path(args.script).resolve().relative_to(ROOT)
        remote_path = "/opt/campus-siem/" + relative.as_posix()
        script_runner = "sudo python3 -c 'import pathlib,subprocess,sys; p=pathlib.Path(sys.argv[1]); p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(sys.stdin.buffer.read()); sys.exit(subprocess.run([\"bash\",str(p)],stdin=subprocess.DEVNULL).returncode)' " + shlex.quote(remote_path)
    command = connection(args.role) + ([script_runner] if args.script else [args.command])
    content = Path(args.script).read_text(encoding="utf-8") if args.script else None
    # Bytes preserve Linux LF endings when the controller runs on Windows.
    result = subprocess.run(command, input=content.encode("utf-8") if content is not None else None)
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
