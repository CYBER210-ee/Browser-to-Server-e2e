"""
server/main.py — EchoVault echo server (protocol v1 + ADR 212 history)

Endpoints:
  GET /api/health   → {"status":"ok"}
  GET /api/status   → {"status":"online","websocket_route":"/ws"}
  GET /pubkey       → {server_x25519, server_ed25519, sig}  (§5.1)
  GET /api/pubkey   → alias (backward compat)
  WS  /ws           → HPKE echo + stored history, strict state machine (§5.6)
  WS  /ws/plain     → plaintext echo — demo exhibit (b): E2E OFF, no history
"""

import asyncio
import json
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
HISTORY: HistoryService | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Stores open at startup (fail loudly if the DB is misconfigured — D024) and
    # the sweeper erases expired epoch keys on a timer as well as per connection.
    global HISTORY
    HISTORY = open_history_service()
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
        "status": "online", "websocket_route": "/ws"
    })


def _pubkey_payload() -> dict:
    """Build /pubkey response with fresh Ed25519 signature (§5.1)."""
    t   = build_t_pubkey(SERVER_KEYS.x25519_pub_bytes, SERVER_KEYS.ed25519_pub_bytes)
    sig = SERVER_KEYS.ed25519_priv.sign(t)
    return {
        "server_x25519":  b64url_encode(SERVER_KEYS.x25519_pub_bytes),
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


# ── WebSocket: plaintext echo — demo exhibit (b): E2E OFF ─────────────────────

@app.websocket("/ws/plain")
async def ws_plain(websocket: WebSocket):
    """
    Plaintext echo — no HPKE, no history.
    mitmproxy sees the prompt in cleartext: demonstrates TLS-alone limitation.

    Message blocks mirror the secure channel but use 'text' where /ws uses 'ct':
      client → {"type":"msg", "seq": N, "text": "..."}
      server → {"type":"msg", "seq": N, "text": "ECHO: ...", "plaintext": true}

    Invariants:
      * A frame carrying 'ct' (or missing 'text') is rejected — close 4002.
        Sealed traffic belongs on /ws only; this keeps the two modes disjoint.
      * An echo is emitted ONLY in direct response to a received plaintext
        transmit (transmits_seen gate) — the server never originates a
        plaintext echo the client didn't ask for.
    """
    await websocket.accept()
    transmits_seen = 0
    try:
        while True:
            raw = await websocket.receive_text()
            try:
                frame = json.loads(raw)
            except Exception:
                await websocket.close(code=4002, reason="malformed frame: expected JSON message block")
                return
            if (
                not isinstance(frame, dict)
                or frame.get("type") != "msg"
                or "ct" in frame
                or not isinstance(frame.get("text"), str)
            ):
                await websocket.close(code=4002, reason="plain endpoint accepts only 'text' message blocks")
                return

            transmits_seen += 1
            if transmits_seen < 1:
                # Defensive: no plaintext echo may leave without a transmit first.
                continue
            await websocket.send_text(json.dumps({
                "type": "msg",
                "seq": frame.get("seq", 0),
                "text": f"ECHO: {frame['text']}",
                "plaintext": True,
            }))
    except WebSocketDisconnect:
        pass
