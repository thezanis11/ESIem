#!/bin/bash
# Compose post-start hook: custom groups must be writable by Wazuh's remoted.
set -euo pipefail
ready=no
for attempt in $(seq 1 90); do
  status=$(/var/ossec/bin/wazuh-control status 2>/dev/null || true)
  if [[ "$status" == *"wazuh-analysisd is running"* ]]; then ready=yes; break; fi
  sleep 2
done
[[ $ready == yes ]] || { echo 'Manager did not become ready for group setup.' >&2; exit 1; }
for group in linux gateway windows; do
  directory="/var/ossec/etc/shared/$group"
  [[ -f "$directory/agent.conf" ]] || { echo "Missing custom agent group: $group" >&2; exit 1; }
  chown root:wazuh "$directory"
  chmod 0770 "$directory"
  chown root:wazuh "$directory/agent.conf"
  chmod 0640 "$directory/agent.conf"
  if [[ -f "$directory/merged.mg" ]]; then
    chown root:wazuh "$directory/merged.mg"
    chmod 0660 "$directory/merged.mg"
  fi
done
echo 'ESIem group permissions prepared.'
