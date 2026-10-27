# Releases

Versionierung: `vX.Y.Z` – X = Major (nur auf Ansage), Y = neues Feature, Z = Bugfix.

## v0.1.3 – 2026-10-27

### Bugfixes
- Installer: `--dns ""` (kein DNS für Clients, z. B. bei Site-to-Site-Verbindungen) fiel stillschweigend auf
  `1.1.1.1, 9.9.9.9` zurück. Ein leerer Wert wird jetzt übernommen und bleibt auch bei erneutem Ausführen erhalten.

## v0.1.2 – 2026-10-27

### Bugfixes
- Installer: Ein frisch installiertes nginx-Paket startet nicht mehr automatisch mit der Standardseite auf
  Port 80. Ist Port 80 schon belegt (z. B. durch einen Docker-Proxy oder eine WAF), brach `apt` vorher ab.
  Die Standardseite wird nur entfernt, wenn nginx gerade durch das Script installiert wurde.
- Installer: `iptables` wird mit `--no-nat` nicht mehr installiert.
- Installer: Fehler der Paketinstallation werden jetzt klar gemeldet.
- `uninstall.sh --purge` weist darauf hin, wenn nginx nur für Simple-WireGuard installiert wurde.

## v0.1.1 – 2026-10-25

### Dokumentation
- Screenshots (Desktop & iPhone 15 Pro) in der README eingebunden (`docs/screenshots/`).

## v0.1.0 – 2026-10-25

Erstes Release.

### Installer (`install.sh`)
- Idempotent: erneutes Ausführen repariert/aktualisiert, Schlüssel, Peers und Benutzer bleiben erhalten.
- Erkennt **eigene** Vorinstallation (Marker `/etc/simple-wireguard/install.json`, Version + Datum) und
  **fremde** WireGuard-Konfigurationen (Rolle Server/Client, aktiv/inaktiv) und weist klar auf den Unterschied hin.
- Warnt bei aktiven WireGuard-Client-Verbindungen und wenn die SSH-Sitzung über ein WireGuard-Interface läuft.
- Konfliktprüfung: Interface-Name, UDP-Port, Subnetz-Überlappung mit bestehenden Routen.
- GUI-Port Standard **4444**, automatischer Fallback auf **9443**, sonst interaktive Abfrage.
- Erzeugt automatisch ein Self-Signed-Zertifikat für nginx (ECDSA P-256, SAN für Endpoint/Hostname),
  erneuert bei Ablauf/Endpoint-Wechsel; eigenes Zertifikat per `--cert/--key`.
- Minimal-invasiv: keine Firewall-/ufw-Änderungen, keine globalen sysctl-Dateien, bestehende nginx-Sites
  unangetastet. NAT/Forwarding nur über PostUp/PostDown des eigenen Interfaces (`--no-nat` zum Abschalten).
- Unterstützt Ubuntu 22.04 / 24.04 / 26.04 LTS (nginx-HTTP/2-Syntax wird automatisch gewählt).
- `uninstall.sh` (optional `--purge`).

### Sicherheit / Architektur
- Web-App läuft unprivilegiert (User `swg`, systemd-Sandboxing, nur 127.0.0.1) hinter nginx/TLS.
- Kleiner Root-Agent (nur Python-stdlib) mit festem Befehlssatz über Unix-Socket (SO_PEERCRED-geprüft);
  validiert jeden Peer strikt – die GUI kann keine `PostUp`-Befehle o. ä. einschleusen.
- Passwörter mit Argon2id, Geheimnisse (Peer-Keys, TOTP-Secrets, Pushover) Fernet-verschlüsselt.
- TOTP verpflichtend für alle Konten inkl. Replay-Schutz, Konto-Sperre nach 5 Fehlversuchen,
  Rate-Limiting (App + nginx), CSRF-Token, HttpOnly/Secure/SameSite=Strict-Cookies, neue Session-ID nach Login,
  strikte CSP, HSTS.

### Weboberfläche (PWA)
- Dashboard (Interface-Status, Online-Peers, Traffic, Top-Traffic, bald ablaufende Peers, letzte Aktivitäten).
- Peers: anlegen/bearbeiten/aktivieren/deaktivieren/löschen, QR-Code, `.conf`-Download, Preshared Keys,
  Schlüsselrotation, eigener Public Key möglich, Suche & Statusfilter.
- Benutzerverwaltung (Rollen Admin/Viewer), TOTP-Reset & Entsperren per GUI.
- Einstellungen: Peer-Standardwerte, Pushover (verschlüsselt gespeichert, Test-Button), Ereignis-Auswahl.
- Verschlüsseltes Backup/Restore (scrypt + AES-256-GCM, optional inkl. Benutzer).
- Audit-Log mit Filter, eigene Sitzungen einsehen/beenden, Passwortwechsel (bei Erst-Login erzwungen).
- Tooltip an jedem Feld (Hover, Tastatur-Fokus, Tap auf Mobilgeräten), responsive bis iPhone-Größe,
  Bottom-Navigation, Safe-Area-Support, Hell/Dunkel-Design, installierbar als PWA.

### Betrieb
- CLI `swg-admin`: `reset-password`, `reset-totp`, `unlock`, `create-user`, `delete-user`, `list-users`, `logout-all`.
- Logs in `/var/log/simple-wireguard/` (app, audit, agent, nginx, install) mit logrotate.
- Automatisches Deaktivieren abgelaufener Peers, Online/Offline-Erkennung mit optionaler Benachrichtigung.
