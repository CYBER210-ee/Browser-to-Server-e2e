# ── EchoVault echo server (FastAPI + uvicorn) ────────────────────────────────
# Plain-HTTP/WebSocket backend. TLS is terminated upstream by mitmproxy, so this
# container only ever speaks clear ws/http on the internal proxynet network.
FROM python:3.12-slim
WORKDIR /app
# Install deps first so Docker can cache this layer across code changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# hpke_server.py is the crypto core imported by main.py
COPY main.py hpke_server.py secure_link.py history_store.py .env .
# Listens on 8000 inside the container (reachable as server:8000 on proxynet).
EXPOSE 8000
# 0.0.0.0 so the proxy container can reach it. No --reload in production.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]