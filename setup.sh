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
umask 077

# ───── Tmp files tracked for cleanup (see trap below) ─────
INIT_TMP=""
MAN_TMP=""
TS_TMP=""
CMP_TMP=""
SECRETS_TMP=""
DOCKER_INSTALLER_TMP=""
cleanup_tmp() {
  rm -f "$INIT_TMP" "$MAN_TMP" "$TS_TMP" "$CMP_TMP" "$SECRETS_TMP" "$DOCKER_INSTALLER_TMP" 2>/dev/null || true
}
trap cleanup_tmp EXIT INT TERM

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

# ───── Input validators ─────
validate_port() {
  local p="$1"
  [[ "$p" =~ ^[0-9]+$ ]] || die "PORT must be numeric (got: '$p')."
  if (( p < 1 || p > 65535 )); then
    die "PORT must be between 1 and 65535 (got: $p)."
  fi
}

validate_install_dir() {
  local d="$1"
  [[ -n "$d" ]] || die "Install dir cannot be empty."
  if [[ "$d" == *:* ]]; then
    die "Install dir must not contain ':' (clashes with Docker volume syntax): $d"
  fi
}

validate_email() {
  local e="$1"
  if [[ ! "$e" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
    die "Invalid admin email: '$e' (reject quotes/backslashes/spaces)."
  fi
}

validate_password() {
  local p="$1" label="${2:-password}"
  if [[ ${#p} -lt 8 ]]; then
    die "$label must be at least 8 characters (got ${#p})."
  fi
}

# ───── Prerequisites ─────
command -v curl >/dev/null 2>&1 || die "curl is required"

install_docker_fallback_get_docker_com() {
  warn "Falling back to https://get.docker.com installer."
  warn "NOTE: get.docker.com is an unpinned upstream script. Verify integrity before running in production."
  DOCKER_INSTALLER_TMP=$(mktemp)
  if ! curl -fsSL https://get.docker.com -o "$DOCKER_INSTALLER_TMP"; then
    die "Failed to download get.docker.com installer."
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    local sum
    sum=$(sha256sum "$DOCKER_INSTALLER_TMP" | awk '{print $1}')
    warn "Downloaded installer sha256: $sum"
    warn "Compare with the value published by Docker before trusting this host."
  fi
  sh "$DOCKER_INSTALLER_TMP"
  rm -f "$DOCKER_INSTALLER_TMP" || true
  DOCKER_INSTALLER_TMP=""
}

install_docker() {
  local distro_id=""
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    distro_id=$(. /etc/os-release; echo "${ID:-}")
  fi
  case "$distro_id" in
    debian|ubuntu|linuxmint|raspbian)
      info "Attempting distro package install: apt-get install docker.io"
      if command -v sudo >/dev/null 2>&1; then
        if sudo apt-get update && sudo apt-get install -y docker.io; then
          return 0
        fi
      elif [[ $EUID -eq 0 ]]; then
        if apt-get update && apt-get install -y docker.io; then
          return 0
        fi
      fi
      warn "Distro install failed."
      ;;
    fedora|rhel|centos|rocky|almalinux)
      info "Attempting distro package install: dnf install docker"
      if command -v sudo >/dev/null 2>&1; then
        if sudo dnf install -y docker; then
          return 0
        fi
      elif [[ $EUID -eq 0 ]]; then
        if dnf install -y docker; then
          return 0
        fi
      fi
      warn "Distro install failed."
      ;;
    *)
      warn "No distro-package path known for ID='${distro_id}'."
      ;;
  esac
  install_docker_fallback_get_docker_com
}

if ! command -v docker >/dev/null 2>&1; then
  warn "Docker is not installed."
  if [[ "$ASSUME_YES" == "true" ]]; then
    info "Installing Docker (distro package preferred)…"
    install_docker
  else
    read -r -p "Install Docker (distro package preferred, falls back to get.docker.com)? [Y/n] " a
    if [[ -z "$a" || "$a" =~ ^[Yy]$ ]]; then
      install_docker
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
    # Pull 24 bytes of base64 then filter non-alphanum — yields ≥20 safe chars
    TS_PASSWD=$(openssl rand -base64 24 | tr -d '/+=\n' | head -c 20)
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

# ───── Validate all inputs (after defaults/flags/interactive) ─────
validate_port "$PORT"
validate_install_dir "$INSTALL_DIR"
if command -v realpath >/dev/null 2>&1; then
  INSTALL_DIR="$(realpath -m "$INSTALL_DIR")"
fi
validate_install_dir "$INSTALL_DIR"
if [[ "$ENABLE_ACCSDB" == "true" ]]; then
  validate_email "$ADMIN_EMAIL"
fi
if [[ "$ENABLE_TS" == "true" ]]; then
  validate_password "$TS_PASSWD" "TorrServer password"
fi

# Resolve sudo for file ops now that we have final INSTALL_DIR
SUDO=""
if ! mkdir -p "$INSTALL_DIR" 2>/dev/null; then
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else die "Cannot create $INSTALL_DIR"; fi
  $SUDO mkdir -p "$INSTALL_DIR"
fi

# ───── Write files ─────
info "Preparing ${INSTALL_DIR}…"
$SUDO mkdir -p "$INSTALL_DIR/module" "$INSTALL_DIR/dlna"

# Backup existing configs to a dedicated mode-700 backups/ dir (not alongside live config)
BACKUP_DIR="$INSTALL_DIR/backups"
$SUDO mkdir -p "$BACKUP_DIR"
$SUDO chmod 700 "$BACKUP_DIR"
if [[ $EUID -eq 0 ]] || [[ -n "$SUDO" ]]; then
  $SUDO chown root:root "$BACKUP_DIR" 2>/dev/null || true
fi
BACKUP_TS="$(date +%s)"
for f in init.conf module/manifest.json module/TorrServer.conf; do
  if [[ -f "$INSTALL_DIR/$f" ]]; then
    base="$(basename "$f")"
    $SUDO cp -p "$INSTALL_DIR/$f" "$BACKUP_DIR/${base}.${BACKUP_TS}.bak"
  fi
done

# Helper: install a staged tmp file to its target with mode, and root:root when possible
install_config_file() {
  local src="$1" dst="$2" mode="$3"
  $SUDO mv "$src" "$dst"
  $SUDO chmod "$mode" "$dst"
  if [[ $EUID -eq 0 ]] || [[ -n "$SUDO" ]]; then
    $SUDO chown root:root "$dst" 2>/dev/null || true
  fi
}

# init.conf (640 — may contain accsdb accounts)
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
install_config_file "$INIT_TMP" "$INSTALL_DIR/init.conf" 640
INIT_TMP=""
ok "init.conf written"

# manifest.json (644 — non-sensitive)
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
install_config_file "$MAN_TMP" "$INSTALL_DIR/module/manifest.json" 644
MAN_TMP=""
ok "module/manifest.json written"

# TorrServer.conf (600 — contains defaultPasswd)
if [[ "$ENABLE_TS" == "true" ]]; then
  TS_TMP=$(mktemp)
  cat > "$TS_TMP" <<EOF
{
  "defaultPasswd": "$TS_PASSWD"
}
EOF
  install_config_file "$TS_TMP" "$INSTALL_DIR/module/TorrServer.conf" 600
  TS_TMP=""
  ok "module/TorrServer.conf written"
fi

# docker-compose.yml (644 — references only, no secrets inline)
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
install_config_file "$CMP_TMP" "$INSTALL_DIR/docker-compose.yml" 644
CMP_TMP=""

# Secrets stash (readable only by root) — password-recovery for unattended installs
if [[ "$ENABLE_TS" == "true" ]]; then
  SECRETS_FILE="$INSTALL_DIR/.install-secrets"
  SECRETS_TMP=$(mktemp)
  {
    echo "# Lampac install secrets — generated $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# Mode 600, readable by root only. Rotate and delete when copied."
    echo "TS_PASSWD=$TS_PASSWD"
    [[ "$ENABLE_ACCSDB" == "true" ]] && echo "ADMIN_EMAIL=$ADMIN_EMAIL"
  } > "$SECRETS_TMP"
  $SUDO mv "$SECRETS_TMP" "$SECRETS_FILE"
  SECRETS_TMP=""
  $SUDO chmod 600 "$SECRETS_FILE"
  if [[ $EUID -eq 0 ]] || [[ -n "$SUDO" ]]; then
    $SUDO chown root:root "$SECRETS_FILE" 2>/dev/null || true
  fi
fi

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
  # Only echo password when it was auto-generated AND stdin is a TTY.
  # Otherwise: point operator at the root-readable secrets / config files.
  if [[ -n "${GENERATED_PASSWD:-}" && -t 0 ]]; then
    echo "    Password: ${BOLD}${TS_PASSWD}${RST}"
    echo "    ${YLW}(auto-generated — save it now)${RST}"
  else
    echo "    Password: ${YLW}not printed${RST}"
    echo "    TorrServer password written to ${INSTALL_DIR}/module/TorrServer.conf"
    echo "    Read it with: ${CYN}sudo cat ${INSTALL_DIR}/module/TorrServer.conf${RST}"
    echo "    (also saved to ${INSTALL_DIR}/.install-secrets — mode 600)"
  fi
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
