#!/bin/bash
# Install files ONLY. Does not change networking, load firewall rules or enable IPS.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run on the dedicated gateway VM as root.' >&2; exit 1; }
source /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 ]] || { echo 'Expected Ubuntu 24.04 lab VM.' >&2; exit 1; }
here=$(cd -- "$(dirname -- "$0")" && pwd)
apt-get update
apt-get install -y suricata suricata-update nftables python3-yaml
install -d /etc/suricata/rules /var/log/suricata /etc/campus
install -m 0644 "$here/campus.rules" /etc/suricata/rules/campus.rules
python3 "$here/configure_suricata.py" --base /etc/suricata/suricata.yaml --output /etc/suricata/campus.yaml
install -m 0644 "$here/campus.nft" /etc/campus/campus.nft
install -m 0644 "$here/campus-suricata.service" /etc/systemd/system/campus-suricata.service
suricata-update --no-reload
sha256sum /var/lib/suricata/rules/suricata.rules >/etc/campus/et-open.sha256
suricata --build-info >/etc/campus/suricata-build.txt
suricata -T -c /etc/suricata/campus.yaml
nft --check --file /etc/campus/campus.nft
systemctl daemon-reload
echo 'Files validated. Follow docs/DEPLOYMENT_FR.md from the VM console before enabling forwarding or loading rules.'
