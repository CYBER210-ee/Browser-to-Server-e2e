# ── EchoVault echo server (FastAPI + uvicorn, TLS) ───────────────────────────
# Speaks HTTPS/WSS itself on 8443 with its own certificate (D030). The leaf and
# key are mounted at /app/certs/tls (see certs/gen-server-certs.sh), the db CA
# at /app/certs/db-ca.crt; settings come from the compose env_file — nothing
# secret is baked into the image.
FROM python:3.12-slim
WORKDIR /app
# Install deps first so Docker can cache this layer across code changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py hpke_server.py secure_link.py history_store.py generate_keys.py .
EXPOSE 8443
# Shell form so SERVER_NAME (the cert name, D031) expands at start time.
CMD ["sh", "-c", "exec uvicorn main:app --host 0.0.0.0 --port 8443 --ssl-keyfile /app/certs/tls/${SERVER_NAME:-echovault}.key --ssl-certfile /app/certs/tls/${SERVER_NAME:-echovault}.crt"]
