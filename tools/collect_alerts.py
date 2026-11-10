"""Snapshot ingestion without mounting a Docker socket in an application container.

Intended as a manually run SOC-host helper. Repeated snapshots are idempotent.
The caller already has administrator-equivalent Docker access. No credentials printed.
"""
import argparse
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--compose", default="runtime/soc/docker-compose.yml")
    parser.add_argument("--db", default="runtime/incidents.db")
    args = parser.parse_args()
    # Stream stdout directly to the consumer: do not buffer a full daily alerts file.
    producer = subprocess.Popen(["docker", "compose", "-p", "campussentinel", "-f", args.compose,
                                "exec", "-T", "wazuh.manager", "cat", "/var/ossec/logs/alerts/alerts.json"], stdout=subprocess.PIPE)
    try:
        consumer = subprocess.run([sys.executable, "-m", "campus", "ingest", "-", "--db", args.db], stdin=producer.stdout)
        producer.stdout.close()
        producer.wait(timeout=15)
        if producer.returncode or consumer.returncode:
            raise SystemExit(1)
    finally:
        if producer.poll() is None:
            producer.kill()
            producer.wait()


if __name__ == "__main__":
    main()
