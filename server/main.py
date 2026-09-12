"""
server/main.py — EchoVault echo server (protocol v1 + ADR 212 history)

Endpoints:
  GET /api/health   → {"status":"ok"}
  GET /api/status   → {"status":"online","websocket_route":"/ws"}
  GET /pubkey       → {server_ed25519, sig}  (§5.1, D028 — pin confirmation only)
  GET /api/pubkey   → alias (backward compat)
  WS  /ws           → HPKE echo + stored history, strict state machine (§5.6)

There is no plaintext endpoint (D029) and no plain-HTTP listener: run under
uvicorn with --ssl-keyfile/--ssl-certfile (D030, see server/certs/).
"""

import asyncio
import json
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

from hpke_server import (
    ServerKeys, ProtocolError, b64url_encode, load_server_keys, build_t_pubkey,
)
from history_store import HistoryService, open_history_service
from secure_link import serve_secure_link

load_dotenv()

SERVER_KEYS: ServerKeys = load_server_keys()
# This server's name (D031): its TLS cert name, and what its records are filed
# under in the shared database. Inert with one server; the seam for many.
SERVER_NAME: str = os.environ.get("SERVER_NAME", "echovault").strip() or "echovault"
HISTORY: HistoryService | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Stores open at startup (fail loudly if the DB is misconfigured — D024) and
    # the sweeper erases expired epoch keys on a timer as well as per connection.
    global HISTORY
    HISTORY = open_history_service(SERVER_NAME)
    # The out-of-band pin (§4.1.1): read it off this console, never off the wire.
    print(f"[echovault] server pin (Ed25519, base64url): {b64url_encode(SERVER_KEYS.ed25519_pub_bytes)}")
    sweeper = asyncio.create_task(HISTORY.run_sweeper())
    try:
        yield
    finally:
        sweeper.cancel()
        HISTORY.close()


app = FastAPI(lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET"])  # demo only


# ── HTTP ───────────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def get_health():
    return JSONResponse(status_code=200, content={"status": "ok"})


@app.get("/api/status")
async def get_status():
    return JSONResponse(status_code=200, content={
        "status": "online", "websocket_route": "/ws", "server": SERVER_NAME,
    })


def _pubkey_payload() -> dict:
    """Build /pubkey response: the Ed25519 pin confirmation only (§5.1, D028)."""
    t   = build_t_pubkey(SERVER_KEYS.ed25519_pub_bytes)
    sig = SERVER_KEYS.ed25519_priv.sign(t)
    return {
        "server_ed25519": b64url_encode(SERVER_KEYS.ed25519_pub_bytes),
        "sig":            b64url_encode(sig),
    }


@app.get("/pubkey")
async def get_pubkey():
    return JSONResponse(status_code=200, content=_pubkey_payload())


@app.get("/api/pubkey")   # backward compat alias
async def get_pubkey_alias():
    return JSONResponse(status_code=200, content=_pubkey_payload())


# ── WebSocket: strict HPKE protocol (§5.6) ────────────────────────────────────

@app.websocket("/ws")
async def ws_hpke(websocket: WebSocket):
    """
    Strict HPKE echo endpoint. Any protocol fault → close 4001; no plaintext fallback.
    """
    await websocket.accept()
    try:
        await serve_secure_link(websocket.receive_text, websocket.send_text, SERVER_KEYS, HISTORY)
    except WebSocketDisconnect:
        pass
    except ProtocolError as e:
        print(f"[protocol] {e}")
        try:
            # Surface the fault class in the close reason (≤123 bytes) so the
            # client can auto-re-establish on the plaintext-on-secure case.
            await websocket.close(code=4001, reason=str(e)[:120] or "protocol error")
        except Exception:
            pass
    except Exception as e:
        print(f"[error] {type(e).__name__}")
        try:
            await websocket.close(code=4001, reason="internal error")
        except Exception:
            pass
