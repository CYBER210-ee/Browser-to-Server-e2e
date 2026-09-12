"""
secure_link.py — the /ws frame loop, independent of the transport (§5.6)

Kept apart from main.py so the whole secure link — handshake, history push,
epoch_key filing, structured msg → echo — can be driven by plain coroutines in
tests, and so main.py stays the thin FastAPI shell.
"""

import json
from typing import Awaitable, Callable

from hpke_server import ServerKeys, ServerSession, ProtocolError, parse_msg_plaintext
from history_store import EpochExists, HistoryService



Recv = Callable[[], Awaitable[str]]
Send = Callable[[str], Awaitable[None]]


async def serve_secure_link(recv: Recv, send: Send, keys: ServerKeys, history: HistoryService) -> None:
    """
    One HPKE connection, start to finish (§5.6):
      AWAIT_HELLO → (hello) → server_hello + history push → ESTABLISHED → (msg | epoch_key)…
    Raises ProtocolError on any protocol fault; the caller closes the transport.
    Split from the WebSocket so tests can drive it with plain coroutines.
    """
    session = ServerSession(keys=keys)

    while True:
        try:
            frame = json.loads(await recv())
        except Exception as e:
            raise ProtocolError(f"malformed/non-JSON frame: {e}")
        if not isinstance(frame, dict):
            raise ProtocolError("frame is not a JSON object")

        frame_type = frame.get("type")

        if session.phase == "AWAIT_HELLO":
            if frame_type != "hello":
                raise ProtocolError(f"expected hello in AWAIT_HELLO, got {frame_type!r}")
            server_hello = session.handle_hello(frame)
            await send(json.dumps(server_hello))
            # History push is the first s2c sealed frame (seq 0), sent without
            # waiting: the browser needs its epoch keys before it can seal (§5.4.2).
            await send(json.dumps(session.seal_history(await history.history_for(session.owner))))

        elif session.phase == "ESTABLISHED":
            if frame_type == "msg":
                # 'text' vs 'ct' discriminator: the secure channel carries ONLY
                # sealed message blocks. A 'text' (plaintext) frame here means
                # the sender fell out of E2E — kill this session so the client
                # must re-establish a brand-new secure connection (fresh
                # handshake, fresh HPKE contexts). Never echo plaintext on /ws.
                if "text" in frame or "ct" not in frame:
                    raise ProtocolError("plaintext frame on secure channel — new secure connection required")
                text, epoch_id, rec_enc, rec_ct = parse_msg_plaintext(session.handle_msg(frame))
                # The record must belong to an epoch we hold for THIS owner (§7.5);
                # it is filed before the echo so a message is never answered but lost.
                if not await history.has_epoch(session.owner, epoch_id):
                    raise ProtocolError("record references an unknown epoch")
                await history.add_record(session.owner, epoch_id, rec_enc, rec_ct)
                reply = session.seal_reply(b"ECHO: " + text.encode("utf-8"))
                await send(json.dumps(reply))

            elif frame_type == "epoch_key":
                epoch_id, enc, ct = session.handle_epoch_key(frame)
                try:
                    await history.add_epoch_key(session.owner, epoch_id, enc, ct)
                except EpochExists:
                    raise ProtocolError("repeated epoch id")

            else:
                raise ProtocolError(f"expected msg/epoch_key in ESTABLISHED, got {frame_type!r}")
