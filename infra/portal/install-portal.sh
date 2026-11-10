#!/bin/bash
set -euo pipefail
[[ $EUID -eq 0 ]] || exit 1
here=$(cd -- "$(dirname -- "$0")" && pwd)
apt-get update
apt-get install -y nginx
install -d -m 0755 /var/www/campus
printf '%s\n' '<!doctype html><html lang="fr"><meta charset="utf-8"><title>Campus Lab</title><h1>Portail universitaire de laboratoire</h1><p>Aucune donnée réelle.</p></html>' >/var/www/campus/index.html
install -m 0644 "$here/campus.conf" /etc/nginx/sites-available/campus
ln -sfn /etc/nginx/sites-available/campus /etc/nginx/sites-enabled/default
nginx -t
systemctl enable --now nginx
systemctl reload nginx
