#!/usr/bin/env bash
# Linkmoth uninstaller. Usage: sudo bash uninstall.sh [--purge]
# Default keeps /etc/linkmoth and /var/lib/linkmoth; --purge removes everything.
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset CDPATH ENV BASH_ENV PYTHONPATH PYTHONHOME

[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }

remove_ca_trust() {
  rm -f /usr/local/share/ca-certificates/linkmoth-local-ca.crt
  if command -v update-ca-certificates >/dev/null; then
    update-ca-certificates >/dev/null 2>&1 || true
  fi
  rm -f /etc/pki/ca-trust/source/anchors/linkmoth-local-ca.crt
  if command -v update-ca-trust >/dev/null; then
    update-ca-trust extract >/dev/null 2>&1 || true
  fi
  rm -f /etc/ca-certificates/trust-source/anchors/linkmoth-local-ca.crt
  if command -v trust >/dev/null; then
    trust extract-compat >/dev/null 2>&1 || true
  fi
}

systemctl disable --now linkmoth 2>/dev/null || true
systemctl disable --now linkmoth-cert-renew.timer 2>/dev/null || true
rm -f /etc/systemd/system/linkmoth.service \
  /etc/systemd/system/linkmoth-cert-renew.service \
  /etc/systemd/system/linkmoth-cert-renew.timer \
  /etc/polkit-1/rules.d/51-linkmoth.rules \
  /usr/local/lib/linkmoth/renew-cert.sh
rmdir /usr/local/lib/linkmoth 2>/dev/null || true
remove_ca_trust
systemctl daemon-reload
rm -rf /opt/linkmoth

if [ "${1:-}" = "--purge" ]; then
  rm -rf /etc/linkmoth /var/lib/linkmoth /etc/systemd/system/linkmoth.service.d
  userdel linkmoth 2>/dev/null || true
  echo "removed service, config, data, and the linkmoth user"
else
  echo "removed service and app; config (/etc/linkmoth) and data (/var/lib/linkmoth) kept"
  echo "run with --purge to remove those too"
fi
