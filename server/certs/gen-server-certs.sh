#!/usr/bin/env bash
# ── Per-server TLS (D030): a project server CA + one leaf per echo server ─────
# Produces, in this directory:
#   server-ca.key / server-ca.crt   → the CA. Browsers trust server-ca.crt for
#                                     local work; the cloud reverse proxy uses it
#                                     to verify each upstream echo server.
#   <SERVER_NAME>.key / .crt        → that server's leaf (uvicorn --ssl-*)
#
# The leaf's SANs must cover every name the server is dialled by:
#   SERVER_NAME=echovault SAN_HOSTS="localhost server echo-a.internal" ./gen-server-certs.sh
#   SAN_IPS="10.0.1.7" ./gen-server-certs.sh          # only if dialled by IP
#
# The CA is reused across runs; FORCE_CA=1 mints a new one (re-trust it everywhere).
set -euo pipefail

SERVER_NAME="${SERVER_NAME:-echovault}"
SAN_HOSTS="${SAN_HOSTS:-localhost server ${SERVER_NAME}}"
SAN_IPS="${SAN_IPS:-127.0.0.1}"

SAN_LIST=""
for h in $SAN_HOSTS; do SAN_LIST+="DNS:${h},"; done
for ip in $SAN_IPS; do SAN_LIST+="IP:${ip},"; done
SAN_LIST="${SAN_LIST%,}"

cd "$(dirname "$0")"

if [[ "${FORCE_CA:-0}" == "1" ]]; then rm -f server-ca.key server-ca.crt; fi
if [[ -f server-ca.key && -f server-ca.crt ]]; then
  echo "[*] Reusing existing server CA. Set FORCE_CA=1 to mint a new one."
else
  echo "[*] Generating server CA..."
  openssl genrsa -out server-ca.key 4096
  openssl req -x509 -new -nodes -key server-ca.key -sha256 -days 1825 \
    -subj "/O=EchoVault/CN=EchoVault Server CA" -extensions v3 -config <(cat <<EOC
[req]
distinguished_name = dn
[dn]
[v3]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOC
) -out server-ca.crt
fi

echo "[*] Generating leaf for ${SERVER_NAME} (SAN: ${SAN_LIST})..."
openssl genrsa -out "${SERVER_NAME}.key" 2048
openssl req -new -key "${SERVER_NAME}.key" -subj "/O=EchoVault/CN=${SERVER_NAME}" -out "${SERVER_NAME}.csr"
cat > "${SERVER_NAME}.ext" <<EOC
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = ${SAN_LIST}
EOC
# 397 days keeps browsers happy with the leaf once the CA is trusted.
openssl x509 -req -in "${SERVER_NAME}.csr" -CA server-ca.crt -CAkey server-ca.key -CAcreateserial \
  -days 397 -sha256 -extfile "${SERVER_NAME}.ext" -out "${SERVER_NAME}.crt"
chmod 644 "${SERVER_NAME}.crt" server-ca.crt
chmod 600 "${SERVER_NAME}.key" server-ca.key
rm -f "${SERVER_NAME}.csr" "${SERVER_NAME}.ext" server-ca.srl
echo "[✓] Done. Trust server-ca.crt in your browser (local) or at the proxy (cloud); keep the .key files here."
openssl x509 -in server-ca.crt -noout -fingerprint -sha256 | sed 's/^/    /'
