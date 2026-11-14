#!/bin/bash
# Daljinski pristup - postavljanje releja na Linux server (Ubuntu / Debian)
#
#   curl -fsSL https://raw.githubusercontent.com/giljevicivan-gif/preuzmi/main/relej/postavi.sh | sudo bash
#
# Ponovno pokretanje iste naredbe = nadogradnja releja (lozinka i registar ostaju).
# Drugi port:  ... | sudo PORT=6000 bash
set -euo pipefail
PORT="${PORT:-50510}"
IZVOR="https://raw.githubusercontent.com/giljevicivan-gif/preuzmi/main/relej/relej_server.py"
MAPA=/opt/daljinski-relej
KORISNIK=daljinski-relej

if [ "$(id -u)" != "0" ]; then echo "Pokreni sa sudo."; exit 1; fi
echo "== Daljinski pristup: postavljam relej (port $PORT) =="
if ! command -v python3 >/dev/null || ! command -v curl >/dev/null; then
  apt-get update -qq && apt-get install -y -qq python3 curl
fi
id "$KORISNIK" >/dev/null 2>&1 || useradd --system --home "$MAPA" --shell /usr/sbin/nologin "$KORISNIK"
mkdir -p "$MAPA"
curl -fsSL "$IZVOR" -o "$MAPA/relej_server.py.novi"
python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$MAPA/relej_server.py.novi"
mv "$MAPA/relej_server.py.novi" "$MAPA/relej_server.py"
if [ ! -s "$MAPA/relej_admin.txt" ]; then
  tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20 > "$MAPA/relej_admin.txt" || true
  echo >> "$MAPA/relej_admin.txt"
fi
chown -R "$KORISNIK:$KORISNIK" "$MAPA"
chmod 600 "$MAPA/relej_admin.txt"

cat > /etc/systemd/system/daljinski-relej.service <<UNIT
[Unit]
Description=Daljinski pristup - relej
After=network-online.target
Wants=network-online.target

[Service]
User=$KORISNIK
WorkingDirectory=$MAPA
Environment=RELEJ_MAPA=$MAPA
ExecStart=/usr/bin/python3 $MAPA/relej_server.py --port $PORT
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=$MAPA
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable daljinski-relej >/dev/null 2>&1
systemctl restart daljinski-relej

if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  ufw allow "$PORT/tcp" >/dev/null && echo "Vatrozid (ufw): otvoren port $PORT"
fi
sleep 2
if systemctl is-active --quiet daljinski-relej; then STANJE="RADI"; else STANJE="NE RADI - pogledaj: journalctl -u daljinski-relej"; fi
IP=$(curl -fsS -4 --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')
echo
echo "================================================================"
echo " Relej: $STANJE"
echo " Adresa za program:   $IP:$PORT"
echo " Admin lozinka (kartica Instalacije):  $(head -n1 "$MAPA/relej_admin.txt")"
echo "================================================================"
echo " Ako server ima vatrozid u web sučelju davatelja (Hetzner, OVH...),"
echo " tamo dopusti dolazni TCP port $PORT."
echo " Dnevnik releja:  journalctl -u daljinski-relej -f"
