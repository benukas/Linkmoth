#!/usr/bin/env bash
# Build dist/ with only files needed to install and run Linkmoth.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
case "$DIST" in
  "$ROOT/dist") ;;
  *) echo "refusing unsafe dist path: $DIST" >&2; exit 1 ;;
esac
FILES=(
  linkmoth.py
  linkmoth_core.py
  linkmoth_probes.py
  linkmoth_engine.py
  linkmoth_handler.py
  linkmoth_backup.py
  linkmoth_auth.py
  linkmoth_discord.py
  linkmoth_kuma_proxy.py
  linkmoth_outage.py
  linkmoth_push.py
  linkmoth_notify.py
  linkmoth_devices.py
  linkmoth_webhooks.py
  dashboard.html
  linkmoth.svg
  linkmoth-white.svg
  linkmoth-mark-white.svg
  linkmoth-maskable.svg
  linkmoth-icon-192.png
  linkmoth-icon-512.png
  linkmoth-white.ico
  sw.js
  manifest.webmanifest
  config.example.json
  README.md
  ADVANCED.md
  CHANGELOG.md
  CONTRIBUTING.md
  TRADEMARKS.md
  LICENSE
  SECURITY.md
  THIRD_PARTY_NOTICES.md
  install.sh
  uninstall.sh
  renew-cert.sh
  linkmoth.service
  linkmoth-cert-renew.service
  linkmoth-cert-renew.timer
)

rm -rf -- "$DIST"
mkdir -p "$DIST"
for f in "${FILES[@]}"; do
  cp "$ROOT/$f" "$DIST/$f"
done
echo "dist/ updated (${#FILES[@]} files)"
