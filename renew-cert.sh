#!/usr/bin/env bash
# Renew Linkmoth' server certificate using its private local CA.
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset CDPATH ENV BASH_ENV PYTHONPATH PYTHONHOME

TLS=/etc/linkmoth/tls
NO_RESTART=0
[ "${1:-}" != "--no-restart" ] || NO_RESTART=1

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
[ -f "$TLS/ca.key" ] && [ -f "$TLS/ca.crt" ] \
  || { echo "Linkmoth local CA is missing" >&2; exit 1; }

TMP="$(mktemp -d "$TLS/.renew.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
umask 077

HOST_SHORT="$(hostname -s 2>/dev/null || hostname)"
HOST_FQDN="$(hostname -f 2>/dev/null || hostname)"
SAN="DNS:localhost,DNS:$HOST_SHORT"
if [ "$HOST_FQDN" != "$HOST_SHORT" ]; then
  SAN="$SAN,DNS:$HOST_FQDN"
fi
for addr in $(hostname -I 2>/dev/null); do
  SAN="$SAN,IP:$addr"
done
SAN="$SAN,IP:127.0.0.1,IP:::1"

cat > "$TMP/server.ext" <<EOF
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = $SAN
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF

openssl req -newkey rsa:3072 -sha256 -nodes \
  -subj "/CN=$HOST_SHORT" -keyout "$TMP/server.key" -out "$TMP/server.csr"
openssl x509 -req -sha256 -days 397 -in "$TMP/server.csr" \
  -CA "$TLS/ca.crt" -CAkey "$TLS/ca.key" -CAcreateserial \
  -extfile "$TMP/server.ext" -out "$TMP/server.crt"
openssl verify -CAfile "$TLS/ca.crt" "$TMP/server.crt"
KEY_FP="$(openssl pkey -in "$TMP/server.key" -pubout | openssl sha256)"
CERT_FP="$(openssl x509 -in "$TMP/server.crt" -pubkey -noout | openssl sha256)"
[ "$KEY_FP" = "$CERT_FP" ] || { echo "generated certificate/key mismatch" >&2; exit 1; }

chown root:linkmoth "$TMP/server.key"
chown root:root "$TMP/server.crt"
chmod 640 "$TMP/server.key"
chmod 644 "$TMP/server.crt"
mv -f "$TMP/server.key" "$TLS/server.key"
mv -f "$TMP/server.crt" "$TLS/server.crt"

if [ "$NO_RESTART" -eq 0 ] && systemctl is-active --quiet linkmoth.service; then
  systemctl restart linkmoth.service
fi
