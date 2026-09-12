#!/usr/bin/env bash
# ── Generate a CA + server cert for the history database (D024) ──────────────
# Produces, in ./certs:
#   db-ca.key / db-ca.crt    → the CA. COPY db-ca.crt to the echo server host;
#                              it is what `sslmode=verify-full` checks against.
#   db.key / db.crt          → the Postgres server cert (SAN = the hostnames)
#
# verify-full checks the HOSTNAME the server dials against the SANs, so list
# every name the server might use: the compose service name (`db`), localhost
# for a local psql, and the DNS name of the box if the DB runs remotely:
#   SAN_HOSTS="db localhost echo.db.test" ./gen-db-certs.sh
#   SAN_IPS="10.188.199.221" ./gen-db-certs.sh      # only if you dial by IP
#
# The CA is reused across runs (same as mitmproxy/gen-certs.sh); only the leaf
# is reissued. FORCE_CA=1 mints a new CA — then redistribute db-ca.crt.
set -euo pipefail

SAN_HOSTS="${SAN_HOSTS:-db localhost echo.db.test}"
SAN_IPS="${SAN_IPS:-}"

SAN_LIST=""
CN=""
for h in $SAN_HOSTS; do
  [[ -z "$CN" ]] && CN="$h"
  SAN_LIST+="DNS:${h},"
done
for ip in $SAN_IPS; do
  SAN_LIST+="IP:${ip},"
done
SAN_LIST="${SAN_LIST%,}"

cd "$(dirname "$0")"
mkdir -p certs
cd certs

if [[ "${FORCE_CA:-0}" == "1" ]]; then
  rm -f db-ca.key db-ca.crt
fi

if [[ -f db-ca.key && -f db-ca.crt ]]; then
  echo "[*] Reusing existing CA (db-ca.key/db-ca.crt). Set FORCE_CA=1 to mint a new one."
else
  echo "[*] Generating DB CA..."
  openssl genrsa -out db-ca.key 4096
  openssl req -x509 -new -nodes -key db-ca.key -sha256 -days 1825 \
    -subj "/O=CYBER210/CN=EchoVault History DB CA" -extensions v3 -config <(cat <<EOC
[req]
distinguished_name = dn
[dn]
[v3]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOC
) -out db-ca.crt
fi

echo "[*] Generating server key + CSR..."
openssl genrsa -out db.key 2048
openssl req -new -key db.key -subj "/O=CYBER210/CN=${CN}" -out db.csr

cat > db.ext <<EOC
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = ${SAN_LIST}
EOC

echo "[*] Signing server cert with the CA (SAN: ${SAN_LIST})..."
openssl x509 -req -in db.csr -CA db-ca.crt -CAkey db-ca.key -CAcreateserial \
  -days 397 -sha256 -extfile db.ext -out db.crt
chmod 644 db.crt db-ca.crt
chmod 600 db.key db-ca.key

rm -f db.csr db.ext db-ca.srl
echo "[✓] Done. Give ./certs/db-ca.crt to the echo server; keep db-ca.key and db.key private."
