"""Overlay lab choices on the distribution's complete, version-matched config.

In particular, retain protocol/port variables required by the ET Open ruleset.
"""
import argparse
from pathlib import Path
import yaml


def merge(base, overlay):
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            merge(base[key], value)
        else:
            base[key] = value
    return base


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    base = yaml.safe_load(Path(args.base).read_text())
    overlay = yaml.safe_load(Path(__file__).with_name("suricata.yaml").read_text())
    result = merge(base, overlay)
    Path(args.output).write_text("%YAML 1.1\n---\n" + yaml.safe_dump(result, sort_keys=False))


if __name__ == "__main__":
    main()
