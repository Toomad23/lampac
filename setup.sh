#!/usr/bin/env bash
# Lampac fork (Toomad23/lampac) — universal Docker installer
#
# Quick install (interactive):
#   bash <(curl -fsSL https://raw.githubusercontent.com/Toomad23/lampac/main/setup.sh)
#
# Unattended:
#   curl -fsSL https://raw.githubusercontent.com/Toomad23/lampac/main/setup.sh | \
#     bash -s -- --yes --port 9118 --admin-email me@example.com --ts-passwd 'MyStrong1'
#
# Re-run the script at any time to update the image or rotate settings.

set -euo pipefail

# ───── Defaults (overridable by flags or env) ─────
INSTALL_DIR="${INSTALL_DIR:-/opt/lampac}"
PORT="${PORT:-9118}"
TS_PASSWD="${TS_PASSWD:-}"
ADMIN_EMAIL="${ADMIN_EMAIL:-}"
ADMIN_EXPIRES="${ADMIN_EXPIRES:-2030-01-01T00:00:00}"
IMAGE="${IMAGE:-ghcr.io/toomad23/lampac:main}"
CONTAINER_NAME="${CONTAINER_NAME:-lampac}"
ENABLE_ACCSDB="ask"
ENABLE_TS="true"
ENABLE_DLNA="true"
ENABLE_SISI="false"
ASSUME_YES="false"

# ───── Output helpers ─────
if [[ -t 1 ]]; then
  BOLD=$'\033[1m'; RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; CYN=$'\033[36m'; RST=$'\033[0m'
else
  BOLD=''; RED=''; GRN=''; YLW=''; CYN=''; RST=''
fi
info() { echo "${CYN}[..]${RST} $*"; }
ok()   { echo "${GRN}[ok]${RST} $*"; }
warn() { echo "${YLW}[!!]${RST} $*" >&2; }
die()  { echo "${RED}[xx]${RST} $*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
Lampac fork — universal Docker installer

Usage:
  bash setup.sh [flags]                               # interactive
  curl -fsSL <url>/setup.sh | bash -s -- [flags]       # unattended

Flags:
  --install-dir PATH      Install directory            (default: /opt/lampac)
  --port N                Listen port                  (default: 9118)
  --ts-passwd STRING      TorrServer password (≥8)     (default: auto-generate with --yes)
  --admin-email EMAIL     Add to accsdb.accounts       (optional, enables accsdb)
  --admin-expires DATE    Expiry for admin-email       (default: 2030-01-01T00:00:00)
  --no-accsdb             Disable accsdb (open access)
  --disable-ts            Disable bundled TorrServer
  --disable-dlna          Disable DLNA module
  --enable-sisi           Enable 18+ module
  --image REF             Container image              (default: ghcr.io/toomad23/lampac:main)
  --container-name NAME   Docker container name        (default: lampac)
  --yes, -y               Non-interactive mode
  --help, -h              Show this help

Examples:
  # Interactive — script asks for each value
  bash setup.sh

  # Unattended, generate TS password automatically
  bash setup.sh --yes --admin-email me@example.com

  # Unattended, explicit password + custom port
  bash setup.sh --yes --port 8080 --ts-passwd 'VerySecure1' --admin-email me@x.com

  # Open access (no accsdb), custom install dir
  bash setup.sh --yes --no-accsdb --install-dir /srv/lampac

  # Re-run to update — configs preserved, image pulled fresh
  bash setup.sh --yes
USAGE
}

# ───── Parse flags ─────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-dir)    INSTALL_DIR="$2"; shift 2 ;;
    --port)           PORT="$2"; shift 2 ;;
    --ts-passwd)      TS_PASSWD="$2"; shift 2 ;;
    --admin-email)    ADMIN_EMAIL="$2"; ENABLE_ACCSDB="true"; shift 2 ;;
    --admin-expires)  ADMIN_EXPIRES="$2"; shift 2 ;;
    --no-accsdb)      ENABLE_ACCSDB="false"; shift ;;
    --disable-ts)     ENABLE_TS="false"; shift ;;
    --disable-dlna)   ENABLE_DLNA="false"; shift ;;
    --enable-sisi)    ENABLE_SISI="true"; shift ;;
    --image)          IMAGE="$2"; shift 2 ;;
    --container-name) CONTAINER_NAME="$2"; shift 2 ;;
    --yes|-y)         ASSUME_YES="true"; shift ;;
    --help|-h)        usage; exit 0 ;;
    *)                echo "Unknown flag: $1"; usage; exit 1 ;;
  esac
done

# ───── Prerequisites ─────
command -v curl >/dev/null 2>&1 || die "curl is required"

if ! command -v docker >/dev/null 2>&1; then
  warn "Docker is not installed."
  if [[ "$ASSUME_YES" == "true" ]]; then
    info "Installing Docker via get.docker.com…"
    curl -fsSL https://get.docker.com | sh
  else
    read -r -p "Install Docker via get.docker.com? [Y/n] " a
    if [[ -z "$a" || "$a" =~ ^[Yy]$ ]]; then
      curl -fsSL https://get.docker.com | sh
    else
      die "Docker is required. Aborting."
    fi
  fi
fi

# Determine how to invoke docker
DOCKER="docker"
if ! docker info >/dev/null 2>&1; then
  if command -v sudo >/dev/null 2>&1 && sudo -n docker info >/dev/null 2>&1; then
    DOCKER="sudo docker"
  elif command -v sudo >/dev/null 2>&1; then
    DOCKER="sudo docker"
    warn "Docker requires sudo — you may be prompted for your password."
  else
    die "Cannot run 'docker'. Add your user to the 'docker' group or run this script as root."
  fi
fi

SUDO=""
if ! mkdir -p "$INSTALL_DIR" 2>/dev/null; then
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else die "Cannot create $INSTALL_DIR"; fi
  $SUDO mkdir -p "$INSTALL_DIR"
fi

# ───── Interactive gathering ─────
if [[ "$ASSUME_YES" != "true" ]]; then
  echo
  echo "${BOLD}Lampac fork installer${RST} (Ctrl+C to abort)"
  echo
  read -r -p "Install dir [${INSTALL_DIR}]: " a; [[ -n "$a" ]] && INSTALL_DIR="$a"
  read -r -p "Listen port [${PORT}]: "       a; [[ -n "$a" ]] && PORT="$a"

  if [[ "$ENABLE_ACCSDB" == "ask" ]]; then
    read -r -p "Protect access with accsdb (email+password)? [y/N] " a
    if [[ "$a" =~ ^[Yy]$ ]]; then
      ENABLE_ACCSDB="true"
      while [[ -z "$ADMIN_EMAIL" ]]; do
        read -r -p "  Admin email: " ADMIN_EMAIL
      done
      read -r -p "  Expires (ISO-8601) [${ADMIN_EXPIRES}]: " a; [[ -n "$a" ]] && ADMIN_EXPIRES="$a"
    else
      ENABLE_ACCSDB="false"
    fi
  fi

  read -r -p "Enable bundled TorrServer? [Y/n] " a
  [[ "$a" =~ ^[Nn]$ ]] && ENABLE_TS="false"

  if [[ "$ENABLE_TS" == "true" && -z "$TS_PASSWD" ]]; then
    while :; do
      read -r -s -p "  TorrServer password (≥8 chars, blank=generate): " TS_PASSWD; echo
      if [[ -z "$TS_PASSWD" ]]; then break; fi
      if [[ ${#TS_PASSWD} -lt 8 ]]; then echo "  too short, try again"; continue; fi
      read -r -s -p "  repeat: " CONFIRM; echo
      [[ "$TS_PASSWD" == "$CONFIRM" ]] && break
      echo "  mismatch, try again"
      TS_PASSWD=""
    done
  fi

  read -r -p "Enable DLNA module? [Y/n] " a; [[ "$a" =~ ^[Nn]$ ]] && ENABLE_DLNA="false"
  read -r -p "Enable 18+ module?  [y/N] " a; [[ "$a" =~ ^[Yy]$ ]] && ENABLE_SISI="true"
fi

# ───── Fill in gaps ─────
[[ "$ENABLE_ACCSDB" == "ask" ]] && ENABLE_ACCSDB="false"

if [[ "$ENABLE_TS" == "true" && -z "$TS_PASSWD" ]]; then
  if command -v openssl >/dev/null 2>&1; then
    TS_PASSWD=$(openssl rand -base64 18 | tr -d '/+=' | head -c 20)
  else
    TS_PASSWD=$(head -c 128 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 20)
  fi
  GENERATED_PASSWD="yes"
fi

if [[ "$ENABLE_TS" == "true" && ${#TS_PASSWD} -lt 8 ]]; then
  die "TorrServer password must be ≥8 characters (got ${#TS_PASSWD})."
fi
if [[ "$ENABLE_ACCSDB" == "true" && -z "$ADMIN_EMAIL" ]]; then
  die "--admin-email is required when accsdb is enabled."
fi

# ───── Write files ─────
info "Preparing ${INSTALL_DIR}…"
$SUDO mkdir -p "$INSTALL_DIR/module" "$INSTALL_DIR/dlna"

# Backup existing configs
for f in init.conf module/manifest.json module/TorrServer.conf; do
  if [[ -f "$INSTALL_DIR/$f" ]]; then
    $SUDO cp -p "$INSTALL_DIR/$f" "$INSTALL_DIR/$f.bak.$(date +%s)"
  fi
done

# init.conf
INIT_TMP=$(mktemp)
if [[ "$ENABLE_ACCSDB" == "true" ]]; then
  cat > "$INIT_TMP" <<EOF
{
  "listenport": $PORT,
  "accsdb": {
    "enable": true,
    "maxiptohour": 15,
    "authMesage": "Введите логин (email) и пароль",
    "denyMesage": "Добавьте {account_email} в init.conf",
    "expiresMesage": "Срок доступа {account_email} истёк ({expires})",
    "accounts": {
      "$ADMIN_EMAIL": "$ADMIN_EXPIRES"
    }
  }
}
EOF
else
  cat > "$INIT_TMP" <<EOF
{
  "listenport": $PORT
}
EOF
fi
$SUDO mv "$INIT_TMP" "$INSTALL_DIR/init.conf"
$SUDO chmod 644 "$INSTALL_DIR/init.conf"
ok "init.conf written"

# manifest.json
MAN_TMP=$(mktemp)
cat > "$MAN_TMP" <<EOF
[
  { "enable": $ENABLE_SISI, "dll": "SISI.dll",      "initspace": "SISI.ModInit" },
  { "enable": true,         "dll": "Online.dll" },
  { "enable": true,         "dll": "Catalog.dll",   "initspace": "Catalog.ModInit" },
  { "enable": $ENABLE_DLNA, "dll": "DLNA.dll",      "initspace": "DLNA.ModInit" },
  { "enable": true,         "dll": "JacRed.dll",    "initspace": "Jackett.ModInit" },
  { "enable": $ENABLE_TS,   "dll": "TorrServer.dll","initspace": "TorrServer.ModInit" },
  { "enable": true,         "dll": "Tracks.dll",    "initspace": "Tracks.ModInit" }
]
EOF
$SUDO mv "$MAN_TMP" "$INSTALL_DIR/module/manifest.json"
$SUDO chmod 644 "$INSTALL_DIR/module/manifest.json"
ok "module/manifest.json written"

# TorrServer.conf
if [[ "$ENABLE_TS" == "true" ]]; then
  TS_TMP=$(mktemp)
  cat > "$TS_TMP" <<EOF
{
  "defaultPasswd": "$TS_PASSWD"
}
EOF
  $SUDO mv "$TS_TMP" "$INSTALL_DIR/module/TorrServer.conf"
  $SUDO chmod 640 "$INSTALL_DIR/module/TorrServer.conf"
  ok "module/TorrServer.conf written"
fi

# docker-compose.yml (for reference / future edits)
CMP_TMP=$(mktemp)
MOUNT_TS=""
[[ "$ENABLE_TS" == "true" ]] && MOUNT_TS="      - $INSTALL_DIR/module/TorrServer.conf:/home/module/TorrServer.conf:rw
"
cat > "$CMP_TMP" <<EOF
services:
  lampac:
    image: $IMAGE
    container_name: $CONTAINER_NAME
    network_mode: host
    restart: always
    volumes:
      - $INSTALL_DIR/init.conf:/home/init.conf:ro
      - $INSTALL_DIR/module/manifest.json:/home/module/manifest.json:rw
${MOUNT_TS}      - $INSTALL_DIR/dlna:/home/dlna:rw
EOF
$SUDO mv "$CMP_TMP" "$INSTALL_DIR/docker-compose.yml"
$SUDO chmod 644 "$INSTALL_DIR/docker-compose.yml"

# ───── Pull image, (re)create container ─────
info "Pulling ${IMAGE}…"
$DOCKER pull "$IMAGE" >/dev/null

info "Recreating container '${CONTAINER_NAME}'…"
$DOCKER rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

RUN_ARGS=(
  -d --name "$CONTAINER_NAME"
  --network host
  --restart always
  -v "$INSTALL_DIR/init.conf:/home/init.conf:ro"
  -v "$INSTALL_DIR/module/manifest.json:/home/module/manifest.json:rw"
  -v "$INSTALL_DIR/dlna:/home/dlna:rw"
)
[[ "$ENABLE_TS" == "true" ]] && RUN_ARGS+=(-v "$INSTALL_DIR/module/TorrServer.conf:/home/module/TorrServer.conf:rw")

$DOCKER run "${RUN_ARGS[@]}" "$IMAGE" >/dev/null

# ───── Wait for readiness ─────
info "Waiting for Lampac to accept traffic on port ${PORT}…"
for i in $(seq 1 30); do
  if curl -fs -o /dev/null "http://127.0.0.1:${PORT}/version" 2>/dev/null; then
    ok "Lampac is up (version: $(curl -s http://127.0.0.1:${PORT}/version))"
    break
  fi
  sleep 2
  if [[ $i -eq 30 ]]; then
    warn "Lampac did not respond within 60s — check '$DOCKER logs $CONTAINER_NAME'."
  fi
done

# ───── Summary ─────
HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
[[ -z "$HOST_IP" ]] && HOST_IP="<YOUR-IP>"

echo
echo "${BOLD}═══════════════════════════════════════════════════════════${RST}"
echo "${BOLD}  Lampac is ready${RST}"
echo "${BOLD}═══════════════════════════════════════════════════════════${RST}"
echo
echo "  Web UI:       ${CYN}http://${HOST_IP}:${PORT}${RST}"
echo "  Admin:        ${CYN}http://${HOST_IP}:${PORT}/admin${RST}"
echo "  All plugins:  ${CYN}http://${HOST_IP}:${PORT}/on.js${RST}"
echo
if [[ "$ENABLE_ACCSDB" == "true" ]]; then
  echo "  Access control: ${GRN}accsdb enabled${RST}"
  echo "    Login:    ${ADMIN_EMAIL}"
  echo "    Expires:  ${ADMIN_EXPIRES}"
else
  echo "  Access control: ${YLW}accsdb disabled (open access)${RST}"
fi
if [[ "$ENABLE_TS" == "true" ]]; then
  echo
  echo "  ${BOLD}TorrServer${RST}: ${CYN}http://${HOST_IP}:${PORT}/ts${RST}"
  if [[ "$ENABLE_ACCSDB" == "true" ]]; then
    echo "    Login:    ${ADMIN_EMAIL}"
  else
    echo "    Login:    (any non-empty string — accsdb is off)"
  fi
  echo "    Password: ${BOLD}${TS_PASSWD}${RST}"
  [[ -n "${GENERATED_PASSWD:-}" ]] && echo "    ${YLW}(auto-generated — save it now)${RST}"
fi
echo
echo "  Config directory:  ${INSTALL_DIR}"
echo "  Container:         ${CONTAINER_NAME}"
echo "  Image:             ${IMAGE}"
echo
echo "  Update to latest:  ${CYN}bash setup.sh --yes${RST}"
echo "  Logs:              ${CYN}${DOCKER} logs -f ${CONTAINER_NAME}${RST}"
echo "  Stop:              ${CYN}${DOCKER} stop ${CONTAINER_NAME}${RST}"
echo "${BOLD}═══════════════════════════════════════════════════════════${RST}"
