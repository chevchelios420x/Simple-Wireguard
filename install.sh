#!/usr/bin/env bash
# Simple-WireGuard installer – idempotent. Re-run at any time to upgrade or change settings.
# Usage: sudo bash install.sh [--endpoint HOST] [--port 51820] [--subnet 10.8.0.0/24] [--dns "1.1.1.1, 9.9.9.9"]
#                             [--iface wg0] [--gui-port 4444] [--admin admin] [--cert FILE --key FILE]
#                             [--renew-cert] [--no-nat] [--yes]
#
# Philosophy: minimal footprint. Only adds what the WireGuard server needs; does NOT touch firewall
# (ufw/nftables), global sysctl files or existing nginx sites. NAT/forwarding rules live only in the
# PostUp/PostDown of our own interface (removed when it goes down); disable with --no-nat.
set -Eeuo pipefail
umask 022

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="$(cat "$SCRIPT_DIR/VERSION")"
ROOT=/opt/simple-wireguard
ETC=/etc/simple-wireguard
VAR=/var/lib/simple-wireguard
LOGDIR=/var/log/simple-wireguard
MARKER="$ETC/install.json"
APP_PORT=8088

# ---------- output helpers ----------
if [[ -t 1 ]]; then R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[34m'; BOLD=$'\e[1m'; N=$'\e[0m'; else R= G= Y= B= BOLD= N=; fi
info()  { echo "${B}[i]${N} $*"; }
ok()    { echo "${G}[✓]${N} $*"; }
warn()  { echo "${Y}[!]${N} $*"; }
err()   { echo "${R}[✗]${N} $*" >&2; }
die()   { err "$*"; exit 1; }
hr()    { echo "${BOLD}────────────────────────────────────────────────────────────${N}"; }
trap 'err "Abbruch in Zeile $LINENO (Befehl: $BASH_COMMAND)"' ERR

ASSUME_YES=0; RENEW_CERT=0; NAT=1
OPT_ENDPOINT= OPT_PORT= OPT_SUBNET= OPT_DNS= OPT_IFACE= OPT_GUI_PORT= OPT_CERT= OPT_KEY=
ADMIN_USER=admin

usage() { sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --endpoint) OPT_ENDPOINT="$2"; shift 2 ;;
    --port) OPT_PORT="$2"; shift 2 ;;
    --subnet) OPT_SUBNET="$2"; shift 2 ;;
    --dns) OPT_DNS="$2"; shift 2 ;;
    --iface) OPT_IFACE="$2"; shift 2 ;;
    --gui-port) OPT_GUI_PORT="$2"; shift 2 ;;
    --admin) ADMIN_USER="$2"; shift 2 ;;
    --cert) OPT_CERT="$2"; shift 2 ;;
    --key) OPT_KEY="$2"; shift 2 ;;
    --renew-cert) RENEW_CERT=1; shift ;;
    --no-nat) NAT=0; shift ;;
    -y|--yes) ASSUME_YES=1; shift ;;
    -h|--help) usage ;;
    *) die "Unbekannte Option: $1 (siehe --help)" ;;
  esac
done

confirm() {
  local q="$1" def="${2:-n}" a
  if [[ $ASSUME_YES -eq 1 ]]; then return 0; fi
  if [[ ! -t 0 ]]; then [[ $def == y ]]; return; fi
  read -r -p "$q [$( [[ $def == y ]] && echo J/n || echo j/N )] " a
  a="${a:-$def}"; [[ $a =~ ^[jJyY] ]]
}

json_get() { python3 -c 'import json,sys
try: print(json.load(open(sys.argv[1])).get(sys.argv[2],""))
except Exception: print("")' "$1" "$2"; }

# ---------- preflight ----------
[[ $EUID -eq 0 ]] || die "Bitte mit Root-Rechten ausführen: sudo bash install.sh"
[[ -r /etc/os-release ]] && . /etc/os-release
if [[ "${ID:-}" != "ubuntu" ]]; then
  warn "Getestet für Ubuntu 22.04/24.04/26.04 LTS – erkannt: ${PRETTY_NAME:-unbekannt}"
  confirm "Trotzdem fortfahren?" || exit 1
else
  case "${VERSION_ID:-}" in
    22.04|24.04|26.04) ok "System: $PRETTY_NAME" ;;
    *) warn "Ubuntu ${VERSION_ID:-?} ist nicht offiziell getestet (22.04/24.04/26.04)."; confirm "Fortfahren?" y || exit 1 ;;
  esac
fi
mkdir -p "$LOGDIR"
exec > >(tee -a "$LOGDIR/install.log") 2>&1
echo; hr; echo "${BOLD} Simple-WireGuard Installer v$VERSION$( date '+  (%F %T)')${N}"; hr

# ---------- detect previous installs ----------
PREV_VERSION=""
if [[ -f "$MARKER" ]]; then
  PREV_VERSION="$(json_get "$MARKER" version)"
  PREV_IFACE="$(json_get "$MARKER" iface)"
  PREV_DATE="$(json_get "$MARKER" installed_at)"
  echo
  echo "${G}${BOLD}▶ Bestehende Simple-WireGuard-Installation gefunden (durch dieses Script installiert)${N}"
  echo "    Version: v$PREV_VERSION   Interface: $PREV_IFACE   installiert: $PREV_DATE"
  if [[ "$PREV_VERSION" == "$VERSION" ]]; then
    echo "    → gleiche Version: Installation wird geprüft und repariert (idempotent)."
  else
    echo "    → Update von v$PREV_VERSION auf v$VERSION. Peers, Benutzer und Schlüssel bleiben erhalten."
  fi
fi
OUR_IFACE="${PREV_IFACE:-}"
IFACE="${OPT_IFACE:-${OUR_IFACE:-wg0}}"

# ---------- detect foreign WireGuard setups & client connections ----------
FOREIGN=0; CONFLICT=0
declare -a FOREIGN_LINES=()
active_ifaces=""
command -v wg >/dev/null 2>&1 && active_ifaces="$(wg show interfaces 2>/dev/null || true)"
shopt -s nullglob
declare -A seen=()
for conf in /etc/wireguard/*.conf; do
  name="$(basename "$conf" .conf)"; seen[$name]=1
  [[ -n "$OUR_IFACE" && "$name" == "$OUR_IFACE" ]] && continue
  FOREIGN=1
  if grep -qiE '^\s*ListenPort' "$conf" && ! grep -qiE '^\s*Endpoint' "$conf"; then role="Server"
  elif grep -qiE '^\s*Endpoint' "$conf"; then role="Client"
  else role="unbekannt"; fi
  state="inaktiv"; [[ " $active_ifaces " == *" $name "* ]] && state="AKTIV"
  FOREIGN_LINES+=("$name  (Rolle: $role, Status: $state, Datei: $conf)")
  [[ "$name" == "$IFACE" ]] && CONFLICT=1
done
for name in $active_ifaces; do
  [[ -n "${seen[$name]:-}" || "$name" == "$OUR_IFACE" ]] && continue
  FOREIGN=1; FOREIGN_LINES+=("$name  (aktiv, ohne Datei in /etc/wireguard – z. B. NetworkManager/systemd-networkd)")
  [[ "$name" == "$IFACE" ]] && CONFLICT=1
done
if [[ $FOREIGN -eq 1 ]]; then
  echo
  echo "${Y}${BOLD}▶ FREMDE WireGuard-Konfiguration gefunden (NICHT durch dieses Script erstellt)${N}"
  for l in "${FOREIGN_LINES[@]}"; do echo "    • $l"; done
  echo "    Mögliche Konflikte: gleicher Interface-Name, UDP-Port, überlappende Subnetze, Firewall/NAT-Regeln."
fi

# Active client connections (this host connects *to* another WireGuard server)
CLIENT_ACTIVE=0
for name in $active_ifaces; do
  [[ "$name" == "$OUR_IFACE" ]] && continue
  now=$(date +%s)
  while read -r _pk hs; do
    if [[ "$hs" =~ ^[0-9]+$ && $hs -gt 0 && $((now - hs)) -lt 300 ]]; then
      CLIENT_ACTIVE=1
      warn "Aktive WireGuard-Verbindung auf Interface ${BOLD}$name${N} (letzter Handshake vor $((now - hs)) s)."
    fi
  done < <(wg show "$name" latest-handshakes 2>/dev/null || true)
done
if [[ -n "${SSH_CONNECTION:-}" ]]; then
  ssh_src="${SSH_CONNECTION%% *}"
  ssh_dev="$(ip route get "$ssh_src" 2>/dev/null | grep -oP 'dev \K\S+' || true)"
  if [[ -n "$ssh_dev" ]] && [[ " $active_ifaces " == *" $ssh_dev "* ]]; then
    warn "${BOLD}Ihre SSH-Sitzung läuft über das WireGuard-Interface $ssh_dev!${N} Änderungen an Routing/Firewall können Sie aussperren."
    CLIENT_ACTIVE=1
  fi
fi
[[ $CLIENT_ACTIVE -eq 1 ]] && warn "Die Installation fügt NAT/Forwarding-Regeln hinzu. Bestehende Client-Tunnel bleiben unangetastet, Routing-Überschneidungen sind aber möglich."

if [[ $CONFLICT -eq 1 ]]; then
  free=0; while [[ -e /etc/wireguard/wg$free.conf || " $active_ifaces " == *" wg$free "* ]]; do free=$((free+1)); done
  err "Interface-Name '$IFACE' ist bereits durch eine fremde Konfiguration belegt."
  echo "    Lösung: sudo bash install.sh --iface wg$free"
  exit 2
fi
if [[ $FOREIGN -eq 1 || $CLIENT_ACTIVE -eq 1 ]]; then
  confirm "Trotz der Hinweise fortfahren?" || { info "Abgebrochen – nichts verändert."; exit 1; }
fi

# ---------- resolve settings (flags > previous install > defaults) ----------
SJ="$ETC/server.json"
prev() { [[ -f "$SJ" ]] && json_get "$SJ" "$1" || true; }
PORT="${OPT_PORT:-$(prev listen_port)}"; PORT="${PORT:-51820}"
SUBNET="${OPT_SUBNET:-$(prev subnet)}"; SUBNET="${SUBNET:-10.8.0.0/24}"
DNS="${OPT_DNS:-$(prev dns)}"; DNS="${DNS:-1.1.1.1, 9.9.9.9}"
PREV_GUI_PORT="$(prev gui_port)"
GUI_PORT="${OPT_GUI_PORT:-$PREV_GUI_PORT}"; GUI_PORT="${GUI_PORT:-4444}"
ENDPOINT="${OPT_ENDPOINT:-$(prev endpoint)}"
[[ "$PORT" =~ ^[0-9]+$ && $PORT -ge 1 && $PORT -le 65535 ]] || die "Ungültiger Port: $PORT"
[[ "$GUI_PORT" =~ ^[0-9]+$ && $GUI_PORT -ge 1 && $GUI_PORT -le 65535 && $GUI_PORT -ne 80 ]] || die "Ungültiger GUI-Port: $GUI_PORT"
[[ "$IFACE" =~ ^[a-zA-Z0-9_=+.-]{1,15}$ ]] || die "Ungültiger Interface-Name: $IFACE"
read -r SUBNET SERVER_ADDR PREFIX < <(python3 - "$SUBNET" <<'PY'
import ipaddress, sys
n = ipaddress.ip_network(sys.argv[1], strict=False)
if n.version != 4 or n.prefixlen > 29 or not n.is_private: sys.exit("Subnetz muss ein privates IPv4-Netz mit max. /29 sein")
print(n, next(n.hosts()), n.prefixlen)
PY
) || true
[[ -n "${SERVER_ADDR:-}" ]] || die "Ungültiges Subnetz: ${OPT_SUBNET:-$SUBNET}"

# Subnet overlap with existing routes (excluding our own interface)
overlap="$(ip -4 route show | awk '{print $1, $3}' | python3 -c '
import ipaddress, sys
ours = ipaddress.ip_network(sys.argv[1]); own = sys.argv[2]
for line in sys.stdin:
    dst, dev = (line.split() + ["", ""])[:2]
    if dst == "default" or dev == own: continue
    try:
        if ipaddress.ip_network(dst, strict=False).overlaps(ours): print(dst, "via", dev)
    except ValueError: pass' "$SUBNET" "$IFACE" || true)"
if [[ -n "$overlap" ]]; then
  warn "VPN-Subnetz $SUBNET überlappt mit bestehenden Routen:"; echo "$overlap" | sed 's/^/    • /'
  confirm "Trotzdem verwenden? (sonst mit --subnet ein anderes Netz wählen)" || exit 1
fi
# UDP port already used by someone else?
if ss -Hulpn "sport = :$PORT" 2>/dev/null | grep -q . && ! ip link show "$IFACE" >/dev/null 2>&1; then
  warn "UDP-Port $PORT ist bereits belegt:"; ss -Hulpn "sport = :$PORT" | sed 's/^/    /'
  confirm "Trotzdem fortfahren? (sonst --port wählen)" || exit 1
fi
# GUI port: default 4444 -> fallback 9443 -> ask. A port held by our own nginx vhost counts as free.
port_busy() {
  local h; h="$(ss -Htlpn "sport = :$1" 2>/dev/null || true)"
  [[ -z "$h" ]] && return 1
  [[ "$1" == "$PREV_GUI_PORT" && "$h" == *nginx* ]] && return 1
  return 0
}
pick_gui_port() {
  local p
  if ! port_busy "$GUI_PORT"; then return; fi
  warn "TCP-Port $GUI_PORT ist bereits belegt: $(ss -Htlpn "sport = :$GUI_PORT" | awk '{print $NF}' | head -1)"
  if [[ -z "$OPT_GUI_PORT" && -z "$PREV_GUI_PORT" && "$GUI_PORT" != 9443 ]] && ! port_busy 9443; then
    GUI_PORT=9443; info "Weiche auf Fallback-Port 9443 aus"; return
  fi
  [[ -z "$OPT_GUI_PORT" && "$GUI_PORT" != 9443 ]] && warn "Fallback-Port 9443 ist ebenfalls belegt."
  [[ -t 0 && $ASSUME_YES -eq 0 ]] || die "Kein freier GUI-Port. Bitte angeben: sudo bash install.sh --gui-port <port>"
  while true; do
    read -r -p "Welchen TCP-Port soll die Weboberfläche nutzen? (leer = Abbruch) " p
    [[ -z "$p" ]] && { info "Abgebrochen – nichts verändert."; exit 1; }
    if [[ ! "$p" =~ ^[0-9]+$ || $p -lt 1 || $p -gt 65535 ]]; then warn "Ungültiger Port"; continue; fi
    if port_busy "$p"; then warn "Port $p ist ebenfalls belegt"; continue; fi
    GUI_PORT="$p"; return
  done
}
pick_gui_port
ok "GUI-Port: $GUI_PORT/tcp"

WAN_IF="$(ip -4 route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
[[ -n "$WAN_IF" ]] || die "Kein Default-Interface gefunden"

# ---------- packages ----------
info "Installiere Pakete …"
export DEBIAN_FRONTEND=noninteractive
PKGS=(wireguard wireguard-tools nginx python3 python3-venv openssl iptables logrotate curl ca-certificates)
missing=(); for p in "${PKGS[@]}"; do dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p"); done
if [[ ${#missing[@]} -gt 0 ]]; then
  apt-get update -qq
  apt-get install -y -qq "${missing[@]}" >/dev/null
fi
ok "Pakete vorhanden"

if [[ -z "$ENDPOINT" ]]; then
  ENDPOINT="$(curl -4 -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
  [[ -n "$ENDPOINT" ]] || ENDPOINT="$(ip -4 addr show "$WAN_IF" | grep -oP 'inet \K[0-9.]+' | head -1)"
  info "Endpoint automatisch erkannt: $ENDPOINT (ändern mit --endpoint vpn.example.com)"
fi
[[ "$ENDPOINT" =~ ^[A-Za-z0-9.:-]+$ ]] || die "Ungültiger Endpoint: $ENDPOINT"

# ---------- user & directories ----------
id swg >/dev/null 2>&1 || useradd --system --home-dir "$VAR" --shell /usr/sbin/nologin swg
install -d -m 0755 -o root -g root "$ROOT"
install -d -m 0750 -o root -g swg "$ETC"
install -d -m 0700 -o root -g root "$ETC/tls-private"
install -d -m 0750 -o root -g root "$ETC/tls"
install -d -m 0700 -o swg -g swg "$VAR"
install -d -m 0750 -o swg -g swg "$LOGDIR"
install -d -m 0700 -o root -g root /etc/wireguard
for f in app.log audit.log agent.log; do [[ -f "$LOGDIR/$f" ]] || install -m 0640 -o swg -g swg /dev/null "$LOGDIR/$f"; done

# ---------- application files ----------
info "Installiere Anwendung v$VERSION nach $ROOT …"
rm -rf "$ROOT/app.new" "$ROOT/web.new" "$ROOT/agent.new"
cp -r "$SCRIPT_DIR/app" "$ROOT/app.new"; cp -r "$SCRIPT_DIR/web" "$ROOT/web.new"; cp -r "$SCRIPT_DIR/agent" "$ROOT/agent.new"
for d in app web agent; do rm -rf "${ROOT:?}/$d"; mv "$ROOT/$d.new" "$ROOT/$d"; done
find "$ROOT/app" "$ROOT/web" "$ROOT/agent" -type d -exec chmod 0755 {} + ; find "$ROOT/app" "$ROOT/web" "$ROOT/agent" -type f -exec chmod 0644 {} +
chown -R root:root "$ROOT/app" "$ROOT/web" "$ROOT/agent"
install -m 0644 "$SCRIPT_DIR/VERSION" "$ROOT/VERSION"
install -m 0755 "$SCRIPT_DIR/deploy/swg-admin" /usr/local/sbin/swg-admin

REQ_HASH="$(sha256sum "$ROOT/app/requirements.txt" | cut -d' ' -f1)-$(python3 -c 'import sys;print(sys.version_info[:2])' | tr -d ' ')"
if [[ ! -x "$ROOT/venv/bin/python" || "$(cat "$ROOT/venv/.req-hash" 2>/dev/null)" != "$REQ_HASH" ]]; then
  info "Erzeuge Python-Umgebung (kann einen Moment dauern) …"
  rm -rf "$ROOT/venv"
  python3 -m venv "$ROOT/venv"
  "$ROOT/venv/bin/pip" install -q --upgrade pip
  "$ROOT/venv/bin/pip" install -q -r "$ROOT/app/requirements.txt"
  echo "$REQ_HASH" > "$ROOT/venv/.req-hash"
fi
ok "Python-Umgebung bereit"

# ---------- secrets & server keys (never regenerated) ----------
if [[ ! -f "$ETC/secret.key" ]]; then
  "$ROOT/venv/bin/python" -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())' > "$ETC/secret.key"
  ok "Neuer Verschlüsselungsschlüssel erzeugt"
fi
chown root:swg "$ETC/secret.key"; chmod 0640 "$ETC/secret.key"
if [[ ! -f "$ETC/server.key" ]]; then
  ( umask 077; wg genkey > "$ETC/server.key" )
  ok "Neues Server-Schlüsselpaar erzeugt"
fi
chown root:root "$ETC/server.key"; chmod 0600 "$ETC/server.key"
SERVER_PUB="$(wg pubkey < "$ETC/server.key")"

# NAT/forwarding scoped to our interface only (added on up, removed on down). Nothing persistent.
NAT_RULES=""
if [[ $NAT -eq 1 ]]; then
  NAT_RULES="PostUp = sysctl -q -w net.ipv4.ip_forward=1
PostUp = iptables -I FORWARD -i %i -j ACCEPT; iptables -I FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -s $SUBNET -o $WAN_IF -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -s $SUBNET -o $WAN_IF -j MASQUERADE"
fi

# ---------- interface header (root only; the web app can never change it) ----------
NEW_IFACE_CONF="$(cat <<EOF
# Managed by Simple-WireGuard install.sh. Peers are appended by the agent.
[Interface]
Address = $SERVER_ADDR/$PREFIX
ListenPort = $PORT
PrivateKey = $(cat "$ETC/server.key")
SaveConfig = false
$NAT_RULES
EOF
)"
IFACE_CHANGED=0
if [[ ! -f "$ETC/interface.conf" ]] || [[ "$(cat "$ETC/interface.conf")" != "$NEW_IFACE_CONF" ]]; then
  ( umask 077; printf '%s\n' "$NEW_IFACE_CONF" > "$ETC/interface.conf" ); IFACE_CHANGED=1
fi
chmod 0600 "$ETC/interface.conf"

# Interface renamed on re-run: stop the old one
if [[ -n "$OUR_IFACE" && "$OUR_IFACE" != "$IFACE" ]]; then
  warn "Interface wird von $OUR_IFACE auf $IFACE umgestellt"
  systemctl disable --now "wg-quick@$OUR_IFACE" 2>/dev/null || true
  rm -f "/etc/wireguard/$OUR_IFACE.conf"
fi

python3 - "$SJ" <<PY
import json, sys
json.dump({"iface": "$IFACE", "listen_port": $PORT, "subnet": "$SUBNET", "server_address": "$SERVER_ADDR",
           "endpoint": "$ENDPOINT", "dns": "$DNS", "public_key": "$SERVER_PUB", "gui_port": $GUI_PORT,
           "wan_iface": "$WAN_IF", "mtu": None}, open(sys.argv[1], "w"), indent=2)
PY
chown root:swg "$SJ"; chmod 0640 "$SJ"


# ---------- TLS certificate (self-signed unless provided) ----------
CERT="$ETC/tls/cert.pem"; KEY="$ETC/tls/key.pem"
if [[ -n "$OPT_CERT" || -n "$OPT_KEY" ]]; then
  [[ -f "$OPT_CERT" && -f "$OPT_KEY" ]] || die "--cert und --key müssen existierende Dateien sein"
  install -m 0644 "$OPT_CERT" "$CERT"; install -m 0600 "$OPT_KEY" "$KEY"
  echo "custom" > "$ETC/tls/.source"; ok "Eigenes Zertifikat übernommen"
else
  need_cert=$RENEW_CERT
  [[ -f "$CERT" && -f "$KEY" ]] || need_cert=1
  if [[ $need_cert -eq 0 && "$(cat "$ETC/tls/.source" 2>/dev/null)" != "custom" ]]; then
    openssl x509 -in "$CERT" -noout -checkend $((30*86400)) >/dev/null 2>&1 || { info "Zertifikat läuft bald ab – erneuere"; need_cert=1; }
    openssl x509 -in "$CERT" -noout -ext subjectAltName 2>/dev/null | grep -qF "$ENDPOINT" || { info "Endpoint geändert – erneuere Zertifikat"; need_cert=1; }
  fi
  if [[ $need_cert -eq 1 ]]; then
    if [[ "$ENDPOINT" =~ ^[0-9.]+$ || "$ENDPOINT" == *:* ]]; then SAN="IP:$ENDPOINT"; else SAN="DNS:$ENDPOINT"; fi
    SAN="$SAN,DNS:$(hostname -f 2>/dev/null || hostname),DNS:localhost,IP:127.0.0.1,IP:$SERVER_ADDR"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -sha256 -days 825 \
      -keyout "$KEY" -out "$CERT" -subj "/CN=$ENDPOINT/O=Simple-WireGuard" \
      -addext "subjectAltName=$SAN" -addext "keyUsage=digitalSignature" -addext "extendedKeyUsage=serverAuth" >/dev/null 2>&1
    echo "self-signed" > "$ETC/tls/.source"
    ok "Self-Signed-Zertifikat erzeugt (ECDSA P-256, 825 Tage, SAN: $SAN)"
  fi
fi
chmod 0644 "$CERT"; chmod 0600 "$KEY"; chown root:root "$CERT" "$KEY"
CERT_FP="$(openssl x509 -in "$CERT" -noout -fingerprint -sha256 | cut -d= -f2)"

# ---------- nginx ----------
NGINX_VER="$(nginx -v 2>&1 | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' || echo 1.18.0)"
if printf '%s\n1.25.1\n' "$NGINX_VER" | sort -V -C; then H2_LISTEN=" http2"; H2_ON=""; else H2_LISTEN=""; H2_ON="    http2 on;"; fi
install -m 0644 "$SCRIPT_DIR/deploy/nginx-proxy.inc" "$ETC/nginx-proxy.inc"
sed -e "s/__GUI_PORT__/$GUI_PORT/g" -e "s/__APP_PORT__/$APP_PORT/g" -e "s/__LISTEN_HTTP2__/$H2_LISTEN/g" \
    -e "s/^__HTTP2_ON__$/$H2_ON/" "$SCRIPT_DIR/deploy/nginx.conf" > /etc/nginx/sites-available/simple-wireguard
ln -sf /etc/nginx/sites-available/simple-wireguard /etc/nginx/sites-enabled/simple-wireguard
# Existing nginx sites are left untouched; we only add our own vhost on a dedicated port.
nginx -t >/dev/null 2>&1 || { nginx -t; die "nginx-Konfiguration ungültig"; }

# ---------- systemd, logrotate ----------
sed "s/__APP_PORT__/$APP_PORT/" "$SCRIPT_DIR/deploy/simple-wireguard.service" > /etc/systemd/system/simple-wireguard.service
install -m 0644 "$SCRIPT_DIR/deploy/simple-wireguard-agent.service" /etc/systemd/system/simple-wireguard-agent.service
install -m 0644 "$SCRIPT_DIR/deploy/logrotate" /etc/logrotate.d/simple-wireguard
logrotate -d /etc/logrotate.d/simple-wireguard >/dev/null 2>&1 || warn "logrotate-Konfiguration meldet Warnungen (logrotate -d /etc/logrotate.d/simple-wireguard)"
systemctl daemon-reload

# ---------- start services ----------
systemctl enable -q simple-wireguard-agent simple-wireguard nginx "wg-quick@$IFACE"
systemctl restart simple-wireguard-agent
INIT_OUT="$(/usr/local/sbin/swg-admin init --username "$ADMIN_USER")"
if [[ $IFACE_CHANGED -eq 1 ]] && ip link show "$IFACE" >/dev/null 2>&1; then
  info "Interface-Einstellungen geändert – starte $IFACE neu"
  systemctl stop "wg-quick@$IFACE" || true
fi
systemctl restart simple-wireguard   # applies peers via agent and brings the interface up
systemctl reload-or-restart nginx
for _ in $(seq 1 20); do curl -fsS "http://127.0.0.1:$APP_PORT/api/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "http://127.0.0.1:$APP_PORT/api/health" >/dev/null 2>&1 || die "Web-App startet nicht: journalctl -u simple-wireguard -n 50"
for _ in $(seq 1 10); do ip link show "$IFACE" >/dev/null 2>&1 && break; sleep 0.5; done
ip link show "$IFACE" >/dev/null 2>&1 || systemctl start "wg-quick@$IFACE" || warn "Interface $IFACE nicht aktiv: journalctl -u wg-quick@$IFACE"

NOW="$(date -Is)"
python3 - "$MARKER" <<PY
import json, os, sys
p = sys.argv[1]
old = json.load(open(p)) if os.path.exists(p) else {}
json.dump({"product": "simple-wireguard", "version": "$VERSION", "iface": "$IFACE",
           "installed_at": old.get("installed_at", "$NOW"), "updated_at": "$NOW",
           "history": (old.get("history", []) + ["$VERSION@$NOW"])[-20:]}, open(p, "w"), indent=2)
PY
chmod 0644 "$MARKER"

# ---------- summary ----------
URL="https://$ENDPOINT$( [[ $GUI_PORT -ne 443 ]] && echo ":$GUI_PORT" )"
echo; hr
echo "${G}${BOLD} Simple-WireGuard v$VERSION ist bereit$( [[ -n "$PREV_VERSION" ]] && echo " (vorher v$PREV_VERSION)")${N}"; hr
echo "  Weboberfläche : $URL"
echo "  VPN-Endpoint  : $ENDPOINT:$PORT/udp   Interface: $IFACE   Subnetz: $SUBNET"
echo "  Zertifikat    : SHA256 $CERT_FP"
echo "                  (Self-Signed: Fingerprint beim ersten Aufruf im Browser vergleichen)"
if [[ "$INIT_OUT" == *INITIAL_PASSWORD* ]]; then
  echo
  echo "${Y}${BOLD}  Erster Login (wird nur jetzt angezeigt!)${N}"
  echo "    Benutzer : $(grep -oP 'INITIAL_ADMIN=\K.*' <<<"$INIT_OUT")"
  echo "    Passwort : $(grep -oP 'INITIAL_PASSWORD=\K.*' <<<"$INIT_OUT")"
  echo "    → Beim ersten Login werden Passwortwechsel und TOTP-Einrichtung erzwungen."
fi
echo
echo "  Notfall-CLI   : sudo swg-admin reset-password <user> | reset-totp <user> | unlock <user> | list-users"
echo "  Logs          : $LOGDIR/ (logrotate aktiv) · journalctl -u simple-wireguard"
echo
echo "${BOLD}  Firewall (wird NICHT automatisch geändert – Aufgabe des Admins):${N}"
echo "    • eingehend UDP $PORT (WireGuard) und TCP $GUI_PORT (Weboberfläche, gern nur aus Admin-Netzen)"
if [[ $NAT -eq 1 ]]; then
  echo "    • Forwarding/NAT für $SUBNET → $WAN_IF setzt das Interface selbst (nur solange $IFACE läuft)."
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    echo "    • ufw ist aktiv – Beispiel: ufw allow $PORT/udp; ufw allow $GUI_PORT/tcp; ufw route allow in on $IFACE out on $WAN_IF"
  fi
else
  echo "    • --no-nat: Routing/NAT für $SUBNET muss selbst eingerichtet werden."
fi
hr
