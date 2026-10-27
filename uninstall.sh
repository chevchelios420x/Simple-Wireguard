#!/usr/bin/env bash
# Simple-WireGuard uninstaller. Removes only what install.sh added.
# Usage: sudo bash uninstall.sh [--purge]   (--purge also deletes keys, database and logs)
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "Bitte mit sudo ausführen" >&2; exit 1; }
PURGE=0; [[ "${1:-}" == "--purge" ]] && PURGE=1
MARKER=/etc/simple-wireguard/install.json
[[ -f $MARKER ]] || { echo "Keine Simple-WireGuard-Installation gefunden." >&2; exit 1; }
IFACE="$(python3 -c 'import json;print(json.load(open("'$MARKER'"))["iface"])')"
NGINX_OURS="$(python3 -c 'import json;print(json.load(open("'$MARKER'")).get("nginx_installed_by_us", False))')"
read -r -p "Simple-WireGuard (Interface $IFACE) entfernen?$( [[ $PURGE -eq 1 ]] && echo ' ALLE DATEN werden gelöscht!') [j/N] " a
[[ $a =~ ^[jJyY] ]] || exit 1
systemctl disable --now simple-wireguard simple-wireguard-agent "wg-quick@$IFACE" 2>/dev/null || true
rm -f /etc/systemd/system/simple-wireguard.service /etc/systemd/system/simple-wireguard-agent.service
rm -f /etc/nginx/sites-enabled/simple-wireguard /etc/nginx/sites-available/simple-wireguard /etc/logrotate.d/simple-wireguard
rm -f /usr/local/sbin/swg-admin "/etc/wireguard/$IFACE.conf"
rm -rf /opt/simple-wireguard
systemctl daemon-reload
nginx -t >/dev/null 2>&1 && systemctl reload nginx || true
if [[ $PURGE -eq 1 ]]; then
  rm -rf /etc/simple-wireguard /var/lib/simple-wireguard /var/log/simple-wireguard
  userdel swg 2>/dev/null || true
  echo "Vollständig entfernt. Installierte Pakete (wireguard, nginx, …) bleiben bestehen."
  [[ "$NGINX_OURS" == True ]] && echo "Hinweis: nginx wurde von Simple-WireGuard installiert und wird nicht mehr benötigt: sudo apt purge nginx nginx-common"
else
  echo "Entfernt. Schlüssel/DB/Logs bleiben in /etc/simple-wireguard, /var/lib/simple-wireguard, /var/log/simple-wireguard."
  echo "Erneutes 'sudo bash install.sh' stellt den Server mit denselben Schlüsseln und Peers wieder her."
fi
