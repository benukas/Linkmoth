#!/usr/bin/env bash
# Linkmoth installer for supported Debian-family Linux (Raspberry Pi OS,
# Debian, Ubuntu). Requires systemd, python3 >= 3.9, and root.
#
# The command line only gets Linkmoth running; the real onboarding (certificate
# trust, account, TOTP, network targets, Uptime Kuma) happens in the browser at
# the /setup address printed at the end.
#
# Usage:
#   sudo bash install.sh                    guided install (asks a few questions
#                                            when run from a terminal; otherwise
#                                            uses detected defaults automatically)
#   sudo bash install.sh --advanced         also ask about every install-time choice
#   sudo bash install.sh --non-interactive --bind 192.168.1.50
#                                            unattended install with an explicit bind
# Extra flags: [--doctor] [--with-push] [--bind IPv4]
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset CDPATH ENV BASH_ENV PYTHONPATH PYTHONHOME

APP=/opt/linkmoth
ETC=/etc/linkmoth
STATE=/var/lib/linkmoth
TLS=/etc/linkmoth/tls
UNIT=/etc/systemd/system/linkmoth.service
RENEW_UNIT=/etc/systemd/system/linkmoth-cert-renew.service
RENEW_TIMER=/etc/systemd/system/linkmoth-cert-renew.timer
RENEW_SCRIPT=/usr/local/lib/linkmoth/renew-cert.sh
SRC="$(cd "$(dirname "$0")" && pwd)"

DOCTOR_ONLY=0
WITH_PUSH=0
WITH_PUSH_SET=0
BIND_OVERRIDE=""
MODE=guided            # guided | advanced | noninteractive
while [ $# -gt 0 ]; do
  case "$1" in
    --doctor) DOCTOR_ONLY=1; shift ;;
    --with-push) WITH_PUSH=1; WITH_PUSH_SET=1; shift ;;
    --bind) BIND_OVERRIDE="${2:-}"; [ -n "$BIND_OVERRIDE" ] || { echo "--bind requires an IPv4 address" >&2; exit 2; }; shift 2 ;;
    --advanced) MODE=advanced; shift ;;
    --non-interactive|--noninteractive) MODE=noninteractive; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

die() { echo "ERROR: $*" >&2; exit 1; }

# --- terminal UI helpers -------------------------------------------------
# Colour only when writing to a real terminal (and NO_COLOR is unset), so piped
# or logged output stays clean.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  B=$'\033[1m'; DIMC=$'\033[2m'; GRN=$'\033[32m'; YEL=$'\033[33m'; CYN=$'\033[36m'; X=$'\033[0m'
else
  B=""; DIMC=""; GRN=""; YEL=""; CYN=""; X=""
fi
section() { printf '\n%s==>%s %s%s%s\n' "$CYN$B" "$X" "$B" "$1" "$X"; }
step()    { printf '    %s...%s %s\n' "$DIMC" "$X" "$*"; }
ok()      { printf '    %s\xe2\x9c\x93%s %s\n' "$GRN$B" "$X" "$*"; }
info()    { printf '    %s\n' "$*"; }
note()    { printf '    %s%s%s\n' "$DIMC" "$*" "$X"; }
warn()    { printf '    %s!%s %s\n' "$YEL$B" "$X" "$*" >&2; }

# Interactive prompts read from and write to the controlling terminal directly,
# so they still work when the script itself was piped in (curl | sudo bash) as
# long as a terminal exists; when it does not, callers fall back to defaults.
prompt_enabled() {
  [ "$MODE" = noninteractive ] && return 1
  [ -r /dev/tty ] || return 1
  return 0
}
ask() {  # ask "Question" "default" -> prints the answer (or the default)
  local q="$1" def="$2" ans=""
  if prompt_enabled; then
    printf '    %s%s%s [%s%s%s]: ' "$B" "$q" "$X" "$CYN" "$def" "$X" >/dev/tty
    IFS= read -r ans </dev/tty || ans=""
  fi
  printf '%s' "${ans:-$def}"
}
ask_yn() {  # ask_yn "Question" "y|n" -> returns 0 for yes
  local q="$1" def="$2" ans="" hint="[y/N]"
  [ "$def" = y ] && hint="[Y/n]"
  if prompt_enabled; then
    printf '    %s%s%s %s: ' "$B" "$q" "$X" "$hint" >/dev/tty
    IFS= read -r ans </dev/tty || ans=""
  fi
  case "${ans:-$def}" in [Yy]*) return 0 ;; *) return 1 ;; esac
}

detect_pkg_manager() {
  if command -v apt-get >/dev/null; then echo apt; return; fi
  if command -v dnf >/dev/null; then echo dnf; return; fi
  if command -v pacman >/dev/null; then echo pacman; return; fi
  if command -v zypper >/dev/null; then echo zypper; return; fi
  echo none
}

# Auto-detect a single unambiguous LAN IPv4 address so a fresh install can
# bind to it instead of 0.0.0.0. 0.0.0.0 listens on every interface,
# including VPN/tunnel ones (WireGuard, Tailscale, NordVPN's nordlynx) that
# reach beyond the LAN without any router port-forward — Linkmoth cannot see
# or rule those out, so narrowing the bind is the only real fix. Container
# bridges (Docker/Podman) are excluded too, though they are lower risk
# (host-local, not normally reachable from outside). Prints nothing when
# detection is ambiguous; fresh non-interactive installs then require --bind.
detect_sole_lan_ip() {
  local tunnel_re='^(tun|tap|wg|tailscale|zt|ppp|nordlynx|wgcf|ipsec|utun)'
  local container_re='^(docker|br-|veth|podman|virbr|cni|flannel|cali)'
  local candidates=() iface addr
  while read -r iface addr; do
    [ -z "$iface" ] && continue
    [ "$iface" = "lo" ] && continue
    if [[ "$iface" =~ $tunnel_re ]] || [[ "$iface" =~ $container_re ]]; then
      continue
    fi
    candidates+=("$addr")
  done < <(ip -o -4 addr show 2>/dev/null \
    | sed -nE 's/^[0-9]+:[[:space:]]+([^[:space:]@]+)(@[^[:space:]]+)?[[:space:]]+inet[[:space:]]+([0-9.]+)\/.*/\1 \3/p')
  if [ "${#candidates[@]}" -eq 1 ]; then
    echo "${candidates[0]}"
  fi
}

validate_bind_ipv4() {
  python3 -I - "$1" <<'PY'
import ipaddress
import sys
try:
    address = ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit(1)
raise SystemExit(0 if isinstance(address, ipaddress.IPv4Address) else 1)
PY
}

# Return 0 if we can bind host:port right now, 1 if it is already in use.
# Runs isolated (-I) so a stray PYTHON* env can't alter interpreter behaviour.
port_is_free() {
  python3 -I - "$1" "$2" <<'PY'
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])

family = socket.AF_INET6 if ":" in host else socket.AF_INET
sock = socket.socket(family, socket.SOCK_STREAM)
try:
    sock.bind((host, port))
except OSError:
    raise SystemExit(1)
finally:
    sock.close()
PY
}

require_binary() {
  local bin="$1" hint="$2"
  if command -v "$bin" >/dev/null; then
    return 0
  fi
  echo "ERROR: required command '$bin' not found." >&2
  echo "       $hint" >&2
  return 1
}

install_packages() {
  local pm missing
  pm="$(detect_pkg_manager)"
  missing=""
  command -v ping >/dev/null || missing="$missing ping"
  command -v ip >/dev/null || missing="$missing ip"
  command -v curl >/dev/null || missing="$missing curl"
  command -v openssl >/dev/null || missing="$missing openssl"
  [ -n "$missing" ] || return 0

  echo "installing missing tools:$missing"
  case "$pm" in
    apt)
      local pkgs=""
      command -v ping >/dev/null || pkgs="$pkgs iputils-ping"
      command -v ip >/dev/null || pkgs="$pkgs iproute2"
      command -v curl >/dev/null || pkgs="$pkgs curl"
      command -v openssl >/dev/null || pkgs="$pkgs openssl"
      apt-get update -qq && apt-get install -y -qq $pkgs
      ;;
    dnf)
      local pkgs=""
      command -v ping >/dev/null || pkgs="$pkgs iputils"
      command -v ip >/dev/null || pkgs="$pkgs iproute"
      command -v curl >/dev/null || pkgs="$pkgs curl"
      command -v openssl >/dev/null || pkgs="$pkgs openssl"
      dnf install -y -q $pkgs
      ;;
    pacman)
      local pkgs=""
      command -v ping >/dev/null || pkgs="$pkgs iputils"
      command -v ip >/dev/null || pkgs="$pkgs iproute2"
      command -v curl >/dev/null || pkgs="$pkgs curl"
      command -v openssl >/dev/null || pkgs="$pkgs openssl"
      pacman -Sy --noconfirm --needed $pkgs
      ;;
    zypper)
      local pkgs=""
      command -v ping >/dev/null || pkgs="$pkgs iputils"
      command -v ip >/dev/null || pkgs="$pkgs iproute2"
      command -v curl >/dev/null || pkgs="$pkgs curl"
      command -v openssl >/dev/null || pkgs="$pkgs openssl"
      zypper --non-interactive install --allow-downgrade $pkgs
      ;;
    none)
      require_binary ping "install iputils / iputils-ping for your distro" || exit 1
      require_binary ip "install iproute2 / iproute for your distro" || exit 1
      require_binary curl "install curl for your distro" || exit 1
      require_binary openssl "install openssl for your distro" || exit 1
      return 0
      ;;
  esac
}

install_ca_trust() {
  local ca_src="$TLS/ca.crt"
  if command -v update-ca-certificates >/dev/null; then
    mkdir -p /usr/local/share/ca-certificates
    cp "$ca_src" /usr/local/share/ca-certificates/linkmoth-local-ca.crt
    chmod 644 /usr/local/share/ca-certificates/linkmoth-local-ca.crt
    update-ca-certificates >/dev/null 2>&1
    echo "installed CA into system trust store (update-ca-certificates)"
    return 0
  fi
  if command -v update-ca-trust >/dev/null; then
    mkdir -p /etc/pki/ca-trust/source/anchors
    cp "$ca_src" /etc/pki/ca-trust/source/anchors/linkmoth-local-ca.crt
    update-ca-trust extract
    echo "installed CA into system trust store (update-ca-trust)"
    return 0
  fi
  if command -v trust >/dev/null; then
    mkdir -p /etc/ca-certificates/trust-source/anchors
    cp "$ca_src" /etc/ca-certificates/trust-source/anchors/linkmoth-local-ca.crt
    trust extract-compat >/dev/null 2>&1 || true
    echo "installed CA into system trust store (trust extract-compat)"
    return 0
  fi
  echo "WARNING: could not update the system CA trust store automatically."
  echo "         The Linkmoth host still works; other devices must trust /ca.crt manually."
}

printf '\n%s  Linkmoth installer%s\n' "$B" "$X"
note "network fault diagnosis + LAN dashboard"
case "$MODE" in
  advanced)       note "mode: advanced (you'll be asked about each choice)" ;;
  noninteractive) note "mode: non-interactive (using detected defaults)" ;;
  *) if prompt_enabled; then note "mode: guided (press Enter to accept a default)"
     else note "mode: guided, no terminal attached (using detected defaults)"; fi ;;
esac

section "Checks"
[ "$(id -u)" -eq 0 ] || die "run with sudo: sudo bash install.sh"
ok "running as root"
command -v systemctl >/dev/null || die "systemd is required"
ok "systemd present"
if [ "$DOCTOR_ONLY" -eq 1 ]; then
  [ -f "$APP/linkmoth.py" ] || die "Linkmoth is not installed at $APP"
  id linkmoth >/dev/null 2>&1 || die "Linkmoth service user is missing"
  runuser -u linkmoth -- env -u PYTHONPATH -u PYTHONHOME \
    LINKMOTH_CONFIG="$ETC/config.json" LINKMOTH_STATE_DIR="$STATE" \
    python3 "$APP/linkmoth.py" --doctor
  exit $?
fi
[ -f "$SRC/linkmoth.py" ] || die "linkmoth.py not found next to install.sh"
[ -f "$SRC/linkmoth_auth.py" ] || die "linkmoth_auth.py not found next to install.sh"
[ -f "$SRC/linkmoth_discord.py" ] || die "linkmoth_discord.py not found next to install.sh"
[ -f "$SRC/linkmoth_kuma_proxy.py" ] || die "linkmoth_kuma_proxy.py not found next to install.sh"
[ -f "$SRC/linkmoth_outage.py" ] || die "linkmoth_outage.py not found next to install.sh"
[ -f "$SRC/linkmoth_push.py" ] || die "linkmoth_push.py not found next to install.sh"
[ -f "$SRC/linkmoth_notify.py" ] || die "linkmoth_notify.py not found next to install.sh"
[ -f "$SRC/linkmoth_devices.py" ] || die "linkmoth_devices.py not found next to install.sh"
[ -f "$SRC/linkmoth_webhooks.py" ] || die "linkmoth_webhooks.py not found next to install.sh"
[ -f "$SRC/dashboard.html" ] || die "dashboard.html not found next to install.sh"
[ -f "$SRC/linkmoth.svg" ] || die "linkmoth.svg not found next to install.sh"
[ -f "$SRC/linkmoth-white.svg" ] || die "linkmoth-white.svg not found next to install.sh"
[ -f "$SRC/linkmoth-mark-white.svg" ] || die "linkmoth-mark-white.svg not found next to install.sh"
[ -f "$SRC/linkmoth-white.ico" ] || die "linkmoth-white.ico not found next to install.sh"
[ -f "$SRC/sw.js" ] || die "sw.js not found next to install.sh"
[ -f "$SRC/manifest.webmanifest" ] || die "manifest.webmanifest not found next to install.sh"
[ -f "$SRC/renew-cert.sh" ] || die "renew-cert.sh not found next to install.sh"
[ -f "$SRC/config.example.json" ] || die "config.example.json not found next to install.sh"
[ -f "$SRC/linkmoth.service" ] || die "linkmoth.service not found next to install.sh"
[ -f "$SRC/linkmoth-cert-renew.service" ] || die "certificate renewal service not found"
[ -f "$SRC/linkmoth-cert-renew.timer" ] || die "certificate renewal timer not found"

command -v python3 >/dev/null || die "python3 is required"
python3 -I -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' \
  || die "python 3.9+ required, found $(python3 -V)"
ok "python $(python3 -c 'import platform;print(platform.python_version())')"

section "Prerequisites"
step "checking for ping, ip, curl, openssl..."
install_packages
ok "required tools present"

# --- Configuration --------------------------------------------------------
# Decide the listen address, port, and whether to enable browser push. On a
# fresh install these become the new config.json; on an existing install the
# saved values are kept (changing them silently would break Kuma webhooks and
# bookmarks), so we only offer the push toggle there.
section "Configuration"
FRESH=0
[ -f "$ETC/config.json" ] || FRESH=1
PENDING_BIND=""
PENDING_PORT=""
if [ "$FRESH" -eq 1 ]; then
  DET_IP="$(detect_sole_lan_ip)"
  DEF_BIND="${DET_IP:-127.0.0.1}"
  if [ -n "$BIND_OVERRIDE" ]; then
    validate_bind_ipv4 "$BIND_OVERRIDE" || die "--bind must be a literal IPv4 address"
    PENDING_BIND="$BIND_OVERRIDE"
    PENDING_PORT="8686"
  elif prompt_enabled && { [ "$MODE" = advanced ] || [ "$MODE" = guided ]; }; then
    PENDING_BIND="$(ask "Address other devices use to reach Linkmoth" "$DEF_BIND")"
    validate_bind_ipv4 "$PENDING_BIND" || die "bind address must be a literal IPv4 address"
    if [ "$PENDING_BIND" = "0.0.0.0" ] && ! ask_yn "Listen on every IPv4 interface? This can expose Linkmoth over VPNs" n; then
      die "refusing wildcard bind; choose a LAN IPv4 address or 127.0.0.1"
    fi
    PENDING_PORT="$(ask "Port" "8686")"
    ok "will listen on $PENDING_BIND:$PENDING_PORT"
  elif [ -n "$DET_IP" ]; then
    PENDING_BIND="$DET_IP"
    PENDING_PORT="8686"
    ok "listening on detected LAN address $DET_IP:8686"
  else
    die "could not identify one LAN IPv4 address; use --bind <LAN IPv4> (or --bind 127.0.0.1)"
  fi
else
  CUR_BIND="$(python3 -I -c "import json;print(json.load(open('$ETC/config.json')).get('bind','127.0.0.1'))" 2>/dev/null || echo 127.0.0.1)"
  CUR_PORT="$(python3 -I -c "import json;print(json.load(open('$ETC/config.json')).get('port',8686))" 2>/dev/null || echo 8686)"
  ok "keeping saved address $CUR_BIND:$CUR_PORT (edit $ETC/config.json to change)"
  [ -z "$BIND_OVERRIDE" ] || warn "--bind is ignored on updates to preserve the saved configuration"
fi

# Browser push is opt-in: only offer it on a fresh install when not already
# requested via --with-push, and only when we can actually ask.
if [ "$WITH_PUSH_SET" -eq 0 ] && [ "$FRESH" -eq 1 ] && prompt_enabled \
    && { [ "$MODE" = advanced ] || [ "$MODE" = guided ]; }; then
  if ask_yn "Enable browser push notifications? (installs a small extra package)" n; then
    WITH_PUSH=1
    ok "browser push will be enabled"
  fi
fi

section "Installing"

# Remember the current service state so a failed update can be rolled back to
# the previously working version. Deliberately do NOT stop the running service
# here: new code is staged and validated while the old one keeps serving, and
# the brief swap happens only once everything is ready (see "activate" below).
# This is what keeps a failed package install, cert step, or doctor check from
# leaving the box with no working Linkmoth at all.
IS_UPDATE=0
[ -f "$APP/linkmoth.py" ] && IS_UPDATE=1
PREV_ACTIVE="$(systemctl is-active linkmoth 2>/dev/null || true)"
PREV_ENABLED="$(systemctl is-enabled linkmoth 2>/dev/null || true)"

ROLLBACK_STATE=prepare   # prepare -> activating -> done
STAGE=""
BACKUP_APP=""
BACKUP_UNIT=""
cleanup_and_rollback() {
  local rc=$?
  trap - EXIT
  if [ "$rc" -eq 0 ]; then
    [ -n "$STAGE" ] && rm -rf "$STAGE"
    [ -n "$BACKUP_APP" ] && rm -rf "$BACKUP_APP"
    [ -n "$BACKUP_UNIT" ] && rm -f "$BACKUP_UNIT"
    exit 0
  fi
  # Only roll back if we had already begun swapping in the new version over a
  # working previous install; failures before that leave the old service alone.
  if [ "$ROLLBACK_STATE" = activating ] && [ "$IS_UPDATE" -eq 1 ] && [ -n "$BACKUP_APP" ]; then
    echo "ERROR: update failed - restoring the previous working version" >&2
    cp -a "$BACKUP_APP/." "$APP/" 2>/dev/null || true
    if [ -n "$BACKUP_UNIT" ] && [ -f "$BACKUP_UNIT" ]; then
      cp -a "$BACKUP_UNIT" "$UNIT" 2>/dev/null || true
    fi
    systemctl daemon-reload 2>/dev/null || true
    [ "$PREV_ENABLED" = enabled ] && systemctl enable linkmoth >/dev/null 2>&1 || true
    if [ "$PREV_ACTIVE" = active ]; then
      systemctl start linkmoth 2>/dev/null || true
      echo "previous Linkmoth version restored and restarted." >&2
    fi
  fi
  [ -n "$STAGE" ] && rm -rf "$STAGE"
  [ -n "$BACKUP_APP" ] && rm -rf "$BACKUP_APP"
  [ -n "$BACKUP_UNIT" ] && rm -f "$BACKUP_UNIT"
  exit "$rc"
}
trap cleanup_and_rollback EXIT

if ! id linkmoth >/dev/null 2>&1; then
  useradd --system --shell /usr/sbin/nologin --home-dir "$STATE" linkmoth 2>/dev/null \
    || useradd -r --shell /usr/sbin/nologin --home-dir "$STATE" linkmoth
  echo "created service user 'linkmoth'"
fi

mkdir -p "$APP" "$ETC" "$STATE" "$TLS"
# Older installs may have created the application directory without execute
# permission for the service account. Repair the directory itself on every
# install/update; application files remain root-owned and non-writable.
chown root:root "$APP"
chmod 755 "$APP"
chown root:linkmoth "$ETC"
chmod 750 "$ETC"

# Browser push is strictly opt-in (--with-push): pywebpush goes into a
# private virtualenv next to the app so the core install never runs pip
# and never touches the system Python (PEP 668 on Debian).
VENV="$APP/venv"
install_pywebpush_venv() {
  local py="$VENV/bin/python" package rc
  if python3 -I -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)'; then
    package="pywebpush==2.3.0"
  else
    package="pywebpush==2.0.3"
  fi
  # Installation runs as the unprivileged service account and accepts wheels
  # only, so package build hooks never execute as root.
  chown -R linkmoth:linkmoth "$VENV"
  rc=0
  if ! runuser -u linkmoth -- env -u PYTHONPATH -u PYTHONHOME \
      "$py" -m pip install --quiet --no-cache-dir --only-binary=:all: \
      "$package" --upgrade-strategy only-if-needed \
      || ! runuser -u linkmoth -- env -u PYTHONPATH -u PYTHONHOME \
        "$py" -c 'import pywebpush'; then
    rc=1
  fi
  chown -R root:linkmoth "$VENV"
  chmod -R g+rX,go-w "$VENV"
  return "$rc"
}

if [ "$WITH_PUSH" -eq 1 ]; then
  step "setting up browser push (virtualenv + pywebpush)..."
  setup_ok=0
  if [ ! -x "$VENV/bin/python" ]; then
    if ! python3 -I -m venv --system-site-packages "$VENV" 2>/dev/null; then
      if command -v apt-get >/dev/null; then
        apt-get update -qq && apt-get install -y -qq python3-venv python3-cryptography || true
        python3 -I -m venv --system-site-packages "$VENV" || true
      fi
    fi
  fi
  if [ -x "$VENV/bin/python" ] && install_pywebpush_venv; then
    setup_ok=1
    chown -R root:linkmoth "$VENV"
    chmod -R g+rX "$VENV"
    ok "browser push ready (/opt/linkmoth/venv — not system pip)"
  fi
  if [ "$setup_ok" -eq 0 ]; then
    echo "WARNING: browser push setup failed - continuing without it."
    echo "         Do not use: sudo pip3 install pywebpush (breaks on Debian cryptography)."
    echo "         Retry with: sudo bash install.sh --with-push"
  fi
fi

# Stage the new application files in a temporary directory. The live service
# keeps running off $APP until the swap in the "activate" step, so any failure
# up to that point leaves the previous version untouched and online.
APP_FILES="linkmoth.py linkmoth_auth.py linkmoth_discord.py linkmoth_kuma_proxy.py
linkmoth_outage.py linkmoth_push.py linkmoth_notify.py linkmoth_devices.py
linkmoth_webhooks.py dashboard.html linkmoth.svg linkmoth-white.svg
linkmoth-mark-white.svg linkmoth-white.ico sw.js
manifest.webmanifest"
[ -f "$SRC/linkmoth-build.json" ] && APP_FILES="$APP_FILES linkmoth-build.json"
step "staging application files..."
STAGE="$(mktemp -d)"
chmod 755 "$STAGE"
for f in $APP_FILES; do
  cp "$SRC/$f" "$STAGE/$f"
done
chmod 644 "$STAGE"/*
ok "application files staged"

CONFIG_CREATED=0
if [ ! -f "$ETC/config.json" ]; then
  cp "$SRC/config.example.json" "$ETC/config.json"
  CONFIG_CREATED=1
  # Apply the listen address and port chosen in the Configuration step
  # (defaults: a detected single LAN address, or loopback, and port 8686).
  python3 -I - "$ETC/config.json" "${PENDING_BIND:-127.0.0.1}" "${PENDING_PORT:-8686}" <<'PY'
import json
import sys

path, bind, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
with open(path, encoding="utf-8") as file:
    cfg = json.load(file)
cfg["bind"] = bind
cfg["port"] = port
with open(path, "w", encoding="utf-8") as file:
    json.dump(cfg, file, indent=2)
    file.write("\n")
PY
  ok "created $ETC/config.json"
  case "${PENDING_BIND:-127.0.0.1}" in
    0.0.0.0|::) note "listening on all interfaces; set \"bind\" in $ETC/config.json to narrow it" ;;
  esac
fi
chown root:linkmoth "$ETC/config.json"
chmod 640 "$ETC/config.json"
python3 -I -m json.tool "$ETC/config.json" >/dev/null \
  || die "$ETC/config.json is not valid JSON"
PORT="$(python3 -I -c "import json;print(json.load(open('$ETC/config.json')).get('port',8686))")"
BIND="$(python3 -I -c "import json;print(json.load(open('$ETC/config.json')).get('bind','127.0.0.1'))")"
case "$BIND" in
  0.0.0.0|::) HEALTH_HOST=127.0.0.1 ;;
  *) HEALTH_HOST="$BIND" ;;
esac

# If the configured port is occupied, roll forward to the next free one rather
# than failing. The currently running Linkmoth (on an update) still holds the
# port at this point and is not a real conflict, so leave it alone in that case.
if ! port_is_free "$BIND" "$PORT" \
    && ! { [ "$IS_UPDATE" -eq 1 ] && [ "$PREV_ACTIVE" = active ]; }; then
  FOUND_PORT=""
  CAND=$((PORT + 1))
  while [ "$CAND" -le 65535 ] && [ "$CAND" -lt $((PORT + 500)) ]; do
    if port_is_free "$BIND" "$CAND"; then
      FOUND_PORT="$CAND"
      break
    fi
    CAND=$((CAND + 1))
  done
  [ -n "$FOUND_PORT" ] || die "no free port found above $PORT on $BIND"
  python3 -I - "$ETC/config.json" "$FOUND_PORT" <<'PY'
import json
import sys

path = sys.argv[1]
port = int(sys.argv[2])

with open(path, encoding="utf-8") as file:
    config = json.load(file)

config["port"] = port

with open(path, "w", encoding="utf-8") as file:
    json.dump(config, file, indent=2)
    file.write("\n")
PY
  warn "port $BIND:$PORT was in use; switched to free port $FOUND_PORT"
  if [ "$CONFIG_CREATED" -eq 0 ]; then
    warn "update any Uptime Kuma webhook and bookmarks to use port $FOUND_PORT"
  fi
  PORT="$FOUND_PORT"
fi

chown -R linkmoth:linkmoth "$STATE"
chmod 750 "$STATE"
[ ! -f "$STATE/auth.json" ] || chmod 600 "$STATE/auth.json"

section "Certificates"
# Create a private local CA once, then renew the server certificate on each
# install so current hostnames and addresses remain valid.
if [ ! -f "$TLS/ca.key" ] || [ ! -f "$TLS/ca.crt" ]; then
  step "generating a private local certificate authority..."
  cat > "$TLS/ca.cnf" <<'EOF'
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no
[dn]
CN = Linkmoth Local CA
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 3650 \
    -config "$TLS/ca.cnf" -keyout "$TLS/ca.key" -out "$TLS/ca.crt" 2>/dev/null
  ok "created Linkmoth local certificate authority"
fi

mkdir -p "$(dirname "$RENEW_SCRIPT")"
cp "$SRC/renew-cert.sh" "$RENEW_SCRIPT"
chown root:root "$RENEW_SCRIPT"
chmod 755 "$RENEW_SCRIPT"

chown root:linkmoth "$TLS"
chown root:root "$TLS/ca.key" "$TLS/ca.crt"
chmod 750 "$TLS"
chmod 600 "$TLS/ca.key"
chmod 644 "$TLS/ca.crt"
step "issuing the server certificate for current addresses..."
"$RENEW_SCRIPT" --no-restart
ok "server certificate ready"

install_ca_trust

sleep 1

section "Activating"
# ---- activate: back up the running version, stop it, and swap in the staged
# code. This is the only window with downtime. From here through the health
# check the EXIT trap will restore and restart the previous version on failure.
ROLLBACK_STATE=activating
if [ "$IS_UPDATE" -eq 1 ]; then
  BACKUP_APP="$(mktemp -d)"
  for f in $APP_FILES; do
    [ -e "$APP/$f" ] && cp -a "$APP/$f" "$BACKUP_APP/$f"
  done
  if [ -f "$UNIT" ]; then
    BACKUP_UNIT="$(mktemp)"
    cp -a "$UNIT" "$BACKUP_UNIT"
  fi
fi

step "swapping in the new version..."
systemctl stop linkmoth >/dev/null 2>&1 || true
for f in $APP_FILES; do
  cp "$STAGE/$f" "$APP/$f"
done

cp "$SRC/linkmoth.service" "$UNIT"
cp "$SRC/linkmoth-cert-renew.service" "$RENEW_UNIT"
cp "$SRC/linkmoth-cert-renew.timer" "$RENEW_TIMER"

step "running preflight doctor..."
runuser -u linkmoth -- env -u PYTHONPATH -u PYTHONHOME LINKMOTH_CONFIG="$ETC/config.json" \
  LINKMOTH_STATE_DIR="$STATE" python3 "$APP/linkmoth.py" --doctor \
  || die "doctor found problems - fix them and re-run"
ok "preflight checks passed"

ONBOARD_TOKEN="$(runuser -u linkmoth -- env -u PYTHONPATH -u PYTHONHOME LINKMOTH_CONFIG="$ETC/config.json" \
  LINKMOTH_STATE_DIR="$STATE" python3 "$APP/linkmoth.py" --auth-onboarding-token)"
WEBHOOK_SECRET="$(runuser -u linkmoth -- env -u PYTHONPATH -u PYTHONHOME LINKMOTH_CONFIG="$ETC/config.json" \
  LINKMOTH_STATE_DIR="$STATE" python3 "$APP/linkmoth.py" --auth-show-webhook)"

# Remove the legacy convenience rule on upgrade. Linkmoth never needs a
# passwordless privilege grant; service administration remains a sudo action.
rm -f /etc/polkit-1/rules.d/51-linkmoth.rules

step "starting the service..."
systemctl daemon-reload
systemctl enable --now linkmoth
systemctl enable --now linkmoth-cert-renew.timer
sleep 2
curl -fs --cacert "$TLS/ca.crt" "https://$HEALTH_HOST:$PORT/health" >/dev/null || {
  journalctl -u linkmoth -n 20 --no-pager
  die "service started but /health does not answer - see log above"
}
ok "service is up and answering /health"
# New version is live and healthy; past this point failures no longer roll back.
ROLLBACK_STATE=done

# Address to show in the access URLs. Prefer the exact bind address when it is
# a concrete IP; otherwise reuse the same careful LAN detection as the config
# step (which excludes VPN/tunnel and container interfaces). Fall back to
# 'hostname -I' only as a last resort, since it can surface a VPN/Docker
# address that isn't reachable from other LAN devices.
if [ "$BIND" != "0.0.0.0" ] && [ "$BIND" != "::" ]; then
  IP="$BIND"
else
  IP="$(detect_sole_lan_ip)"
  [ -n "$IP" ] || IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [ -n "$IP" ] || IP="127.0.0.1"
fi
SETUP_URL="https://$IP:$PORT/setup"

# ---- the one thing a beginner needs: an address and (first time) a code ----
printf '\n%s%sLinkmoth is ready.%s\n' "$B" "$GRN" "$X"
printf '\n'
printf '  %sOpen this on any device on your network:%s\n' "$B" "$X"
printf '     %s%s%s\n' "$B$CYN" "$SETUP_URL" "$X"
if [ -n "$ONBOARD_TOKEN" ]; then
  printf '\n'
  printf '  %sSetup code%s (needed once, expires in 24h):\n' "$B" "$X"
  printf '     %s%s%s\n' "$B$CYN" "$ONBOARD_TOKEN" "$X"
fi
printf '\n'
note "The browser setup walks you through trusting the certificate, creating"
note "your account and TOTP, detecting network targets, and connecting Uptime Kuma."

# ---- details for power users / later reference ----
PUSH_STATE="off (enable anytime: sudo bash install.sh --with-push)"
if [ -x "$VENV/bin/python" ] && runuser -u linkmoth -- \
    env -u PYTHONPATH -u PYTHONHOME "$VENV/bin/python" -c 'import pywebpush' 2>/dev/null; then
  PUSH_STATE="enabled"
fi
section "Details"
info "dashboard:     https://$IP:$PORT"
info "config:        $ETC/config.json"
info "data:          $STATE/state.db"
info "logs:          journalctl -u linkmoth -f"
info "browser push:  $PUSH_STATE"
info "CA cert:       https://$IP:$PORT/ca.crt  (or /usr/local/share/ca-certificates/linkmoth-local-ca.crt)"
info "CA fingerprint: $(openssl x509 -in "$TLS/ca.crt" -noout -fingerprint -sha256 | sed 's/^.*=//')"
printf '\n'
info "Linkmoth checks the network itself every few minutes and raises its own"
info "incidents \342\200\224 no other service is required."
printf '\n'
note "Optional: if you run Uptime Kuma, point it here for instant, per-service"
note "triggering (Settings > Notifications > Webhook):"
note "  URL:     https://$HEALTH_HOST:$PORT/trigger   (JSON)"
note "           use $HEALTH_HOST only if Kuma runs on this host; otherwise https://$IP:$PORT/trigger"
note "  Header:  Authorization: Bearer $WEBHOOK_SECRET"
note "           re-print anytime: sudo -u linkmoth python3 $APP/linkmoth.py --auth-show-webhook"
