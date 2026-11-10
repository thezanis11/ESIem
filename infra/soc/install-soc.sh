#!/bin/bash
# Dedicated Ubuntu SOC VM only; no host firewall changes or public bindings.
set -euo pipefail
[[ $EUID -eq 0 ]] || exit 1
source /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 ]] || { echo 'Expected Ubuntu 24.04 lab VM.' >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl gnupg python3-venv rsyslog
install -d -m 0755 /etc/apt/keyrings
curl --fail --silent --show-error https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
cat >/etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: noble
Components: stable
Architectures: amd64
Signed-By: /etc/apt/keyrings/docker.asc
EOF
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
printf '%s\n' 'vm.max_map_count=262144' >/etc/sysctl.d/90-esiem-indexer.conf
sysctl -p /etc/sysctl.d/90-esiem-indexer.conf
cd /opt/campus-siem
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
docker version --format '{{.Server.Version}}'
docker compose version
echo 'SOC prerequisites installed; no Wazuh stack started by this installer.'
