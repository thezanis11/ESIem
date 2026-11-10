#!/bin/bash
# Run only on a dedicated Ubuntu 24.04 lab endpoint, after its VM networking is ready.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run on the lab VM as root.' >&2; exit 1; }
[[ -f /etc/os-release ]] && source /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 24.04 ]] || { echo 'Expected Ubuntu 24.04 lab VM.' >&2; exit 1; }
apt-get update
apt-get install -y ca-certificates curl gnupg rsyslog auditd
install -d -m 0755 /usr/share/keyrings
key_tmp=$(mktemp)
trap 'rm -f "$key_tmp"' EXIT
curl --fail --silent --show-error https://packages.wazuh.com/key/GPG-KEY-WAZUH -o "$key_tmp"
gpg --batch --yes --dearmor -o /usr/share/keyrings/wazuh.gpg "$key_tmp"
printf '%s\n' 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' >/etc/apt/sources.list.d/wazuh.list
apt-get update
apt-get install -y wazuh-agent=4.14.10-1
apt-mark hold wazuh-agent
python3 - <<'PY'
from pathlib import Path
import xml.etree.ElementTree as E
path=Path('/var/ossec/etc/ossec.conf')
root=E.fromstring('<root>'+path.read_text()+'</root>')
root.find('.//client/server/address').text='10.77.10.10'
client=root.find('.//client')
enrollment=client.find('enrollment')
if enrollment is None: enrollment=E.SubElement(client,'enrollment')
enabled=enrollment.find('enabled')
if enabled is None: enabled=E.SubElement(enrollment,'enabled')
enabled.text='no'
path.write_text('\n'.join(E.tostring(c,encoding='unicode') for c in root))
PY
install -m 0640 "$(dirname "$0")/campus-audit.rules" /etc/audit/rules.d/campus.rules
augenrules --load
systemctl enable --now rsyslog auditd
echo 'Agent installed. Import its unique offline key before starting wazuh-agent.'
