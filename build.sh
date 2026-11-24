#!/usr/bin/env bash
# Gera o instalador unico: instalar-codermax.sh (todos os arquivos embutidos)
set -e
cd "$(dirname "$0")"
OUT=instalar-codermax.sh
PAYLOAD=$(tar -czf - codermax.py web/index.html web/favicon.svg | base64 -w 76)
cat > "$OUT" <<'HEADER'
#!/usr/bin/env bash
# =====================================================================
#  CODERMAX - Instalador completo (script unico)
#  Gateway UDP (modulador/encoder) -> links HLS (.m3u8) / MPEG-TS / M3U
#
#  Uso:   sudo bash instalar-codermax.sh --usuario NOME --senha SENHA
#         sudo bash instalar-codermax.sh --porta 30022     (outra porta)
#         sudo bash instalar-codermax.sh --desinstalar
#
#  Pelo SSH (1 linha):
#   curl -fsSL https://raw.githubusercontent.com/maxdossantosoliveira22-code/codemax/main/instalar-codermax.sh | sudo bash -s -- --usuario NOME --senha SENHA
#
#  - Roda na porta 30022 (TCP), separado do Flussonic.
#  - Captura passiva dos UDP: nao ocupa as portas UDP que o Flussonic usa.
#  - Painel: http://IP_DO_SERVIDOR:30022
#
#  Funciona rodando como arquivo OU colando tudo direto no terminal SSH.
# =====================================================================
set +H 2>/dev/null; true
(
CODERMAX_PAYLOAD=$(cat <<'__CODERMAX_PAYLOAD__'
__PAYLOAD_HERE__
__CODERMAX_PAYLOAD__
)
set -e
APP_DIR=/opt/codermax
SERVICE=codermax
PORT=30022
NEW_USER=""
NEW_PASS=""

verde(){ echo -e "\e[32m$*\e[0m"; }
amarelo(){ echo -e "\e[33m$*\e[0m"; }
vermelho(){ echo -e "\e[31m$*\e[0m"; }

[ "$(id -u)" -eq 0 ] || { vermelho "Rode como root: sudo bash instalar-codermax.sh"; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --porta|--port) PORT="$2"; shift 2 ;;
    --usuario|--user) NEW_USER="$2"; shift 2 ;;
    --senha|--password) NEW_PASS="$2"; shift 2 ;;
    --desinstalar|--uninstall)
      systemctl disable --now $SERVICE 2>/dev/null || true
      rm -f /etc/systemd/system/$SERVICE.service; systemctl daemon-reload
      rm -rf /dev/shm/codermax-hls
      amarelo "Servico removido. Dados/canais mantidos em $APP_DIR/data (apague com: rm -rf $APP_DIR)"
      exit 0 ;;
    *) vermelho "Opcao desconhecida: $1"; exit 1 ;;
  esac
done

echo "== Instalando Codermax (porta $PORT) =="

# --- 1. dependencias -------------------------------------------------
if ! command -v python3 >/dev/null || ! command -v ffmpeg >/dev/null; then
  echo "-> Instalando python3 e ffmpeg..."
  if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq && apt-get install -y -qq python3 ffmpeg iproute2
  elif command -v dnf >/dev/null; then
    dnf install -y epel-release >/dev/null 2>&1 || true
    dnf install -y python3 ffmpeg iproute 2>/dev/null || dnf install -y --nogpgcheck https://mirrors.rpmfusion.org/free/el/rpmfusion-free-release-$(rpm -E %rhel).noarch.rpm && dnf install -y python3 ffmpeg iproute
  elif command -v yum >/dev/null; then
    yum install -y epel-release && yum install -y python3 ffmpeg iproute
  else
    vermelho "Instale python3 e ffmpeg manualmente e rode novamente."; exit 1
  fi
fi
command -v python3 >/dev/null || { vermelho "python3 nao encontrado"; exit 1; }
command -v ffmpeg  >/dev/null || amarelo "AVISO: ffmpeg nao instalado - HLS nao funcionara (TS direto funciona)."
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)' || { vermelho "Precisa Python 3.8+"; exit 1; }

# --- 2. porta livre? ---------------------------------------------------
if systemctl is-active --quiet $SERVICE; then systemctl stop $SERVICE; fi
PORT_HEX=$(printf '%04X' "$PORT")
if awk -v p=":$PORT_HEX" '$4=="0A" && $2 ~ p"$"' /proc/net/tcp /proc/net/tcp6 2>/dev/null | grep -q .; then
  vermelho "A porta $PORT ja esta em uso por outro programa (Flussonic?)."
  vermelho "Escolha outra:  sudo bash instalar-codermax.sh --porta 30023"
  exit 1
fi
if pgrep -fa flussonic >/dev/null 2>&1; then
  verde "-> Flussonic detectado - o Codermax vai rodar isolado na porta $PORT, sem mexer nele."
fi

# --- 3. arquivos -------------------------------------------------------
echo "-> Copiando arquivos para $APP_DIR"
mkdir -p "$APP_DIR/data"
printf '%s\n' "$CODERMAX_PAYLOAD" | base64 -d | tar -xzf - -C "$APP_DIR"
chmod 755 "$APP_DIR/codermax.py"
chmod 700 "$APP_DIR/data"

# porta no config (preserva canais existentes)
CODERMAX_SET_USER="$NEW_USER" CODERMAX_SET_PASS="$NEW_PASS" python3 - "$APP_DIR/data/config.json" "$PORT" <<'PY'
import json, os, sys, hashlib, secrets
p, port = sys.argv[1], int(sys.argv[2])
d = json.load(open(p)) if os.path.exists(p) else {}
d["port"] = port
def h(pw):
    salt = secrets.token_hex(8)
    return "pbkdf2$%s$%s" % (salt, hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 120000).hex())
u, pw = os.environ.get("CODERMAX_SET_USER"), os.environ.get("CODERMAX_SET_PASS")
if u:
    d["admin_user"] = u
if pw:
    d["admin_pass_hash"] = h(pw)
elif not d.get("admin_pass_hash"):
    pw = secrets.token_urlsafe(9)
    d["admin_pass_hash"] = h(pw)
    open(os.path.join(os.path.dirname(p), "senha-inicial.txt"), "w").write(pw + "\n")
d.setdefault("admin_user", "admin")
json.dump(d, open(p, "w"), indent=2, ensure_ascii=False)
os.chmod(p, 0o600)
PY

# --- 4. servico systemd ------------------------------------------------
cat > /etc/systemd/system/$SERVICE.service <<UNIT
[Unit]
Description=Codermax - UDP para HLS/MPEG-TS/M3U
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/env python3 $APP_DIR/codermax.py
WorkingDirectory=$APP_DIR
Environment=PYTHONUNBUFFERED=1
Restart=always
RestartSec=3
# prioridade menor que o Flussonic: nunca disputa CPU com ele
Nice=5
CPUWeight=50
IOSchedulingClass=best-effort
IOSchedulingPriority=6
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now $SERVICE >/dev/null 2>&1

# --- 5. firewall -------------------------------------------------------
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow $PORT/tcp >/dev/null && echo "-> ufw: porta $PORT/tcp liberada"
elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd --permanent --add-port=$PORT/tcp >/dev/null && firewall-cmd --reload >/dev/null && echo "-> firewalld: porta $PORT/tcp liberada"
elif command -v iptables >/dev/null && iptables -S INPUT 2>/dev/null | grep -q -- "-P INPUT DROP"; then
  iptables -C INPUT -p tcp --dport $PORT -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport $PORT -j ACCEPT
  echo "-> iptables: porta $PORT/tcp liberada (salve suas regras para persistir)"
fi

# --- 6. resultado ------------------------------------------------------
sleep 2
IP_LOCAL=$(hostname -I 2>/dev/null | awk '{print $1}')
IP_PUB=$(curl -s -m 4 https://api.ipify.org 2>/dev/null || true)
echo
if systemctl is-active --quiet $SERVICE; then
  verde "=============================================================="
  verde "  CODERMAX INSTALADO E RODANDO"
  verde "=============================================================="
  echo  "  Painel (rede local):  http://${IP_LOCAL:-IP_DO_SERVIDOR}:$PORT"
  [ -n "$IP_PUB" ] && echo "  Painel (externo):     http://$IP_PUB:$PORT"
  echo  "  Usuario:              $(python3 -c "import json;print(json.load(open('$APP_DIR/data/config.json'))['admin_user'])")"
  if [ -n "$NEW_PASS" ]; then echo "  Senha:                (a que voce informou)"
  elif [ -f "$APP_DIR/data/senha-inicial.txt" ]; then echo "  Senha inicial:        $(cat $APP_DIR/data/senha-inicial.txt)   (troque no painel)"; rm -f "$APP_DIR/data/senha-inicial.txt"
  else echo "  Senha:                (mantida a atual)"; fi
  echo
  echo  "  1) Abra o painel > Scanner UDP > escolha a placa do modulador"
  echo  "  2) Clique em Iniciar varredura > + Adicionar nos canais"
  echo  "  3) Em 'Links M3U' copie o link da lista ou de cada canal"
  echo
  echo  "  Comandos: systemctl status|restart|stop $SERVICE"
  echo  "            journalctl -u $SERVICE -f"
  [ -n "$IP_PUB" ] && echo "  Dica: em Configuracoes, informe http://$IP_PUB:$PORT como endereco publico."
else
  vermelho "O servico nao iniciou. Veja: journalctl -u $SERVICE -n 50"
  exit 1
fi
exit 0
)
HEADER
python3 - "$OUT" "$PAYLOAD" <<'PYB'
import sys
p, payload = sys.argv[1], sys.argv[2]
s = open(p).read()
assert s.count("__PAYLOAD_HERE__") == 1
open(p, "w").write(s.replace("__PAYLOAD_HERE__", payload))
PYB
chmod +x "$OUT"
echo "Gerado: $OUT ($(du -h "$OUT" | cut -f1))"
