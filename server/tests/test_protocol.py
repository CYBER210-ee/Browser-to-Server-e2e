"""
Full secure link with a Python-side browser (pyhpke both sides): handshake,
history push, epoch_key upload, structured msg, and the fail-closed gates
(ADR 212 / protocol §5.4.1, §5.4.2, §5.6, §7.5, §9).
"""

import asyncio
import json
import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import hpke_server as H
from history_store import EpochKeyStore, HistoryService, MemoryRecordStore, Policy
from secure_link import serve_secure_link

INFO_EPOCH_KEY = b"echovault/epoch-key/v1"   # §0 item 12
INFO_RECORD    = b"echovault/record/v1"      # §0 item 13


def hpke_seal(pk, pt: bytes, info: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """RFC 9180 single-shot Seal = SetupBaseS + one ContextS.Seal (what hpke-js suite.seal does)."""
    enc, ctx = H.SUITE.create_sender_context(pk, info=info)
    return enc, ctx.seal(pt, aad=aad)


def hpke_open(enc: bytes, sk, ct: bytes, info: bytes, aad: bytes) -> bytes:
    return H.SUITE.create_recipient_context(enc, sk, info=info).open(ct, aad=aad)


# ── A browser, in Python ─────────────────────────────────────────────────────

class PyBrowser:
    """Just enough of page.tsx to exercise the server: identity, handshake, storage seals."""

    def __init__(self, server_keys: H.ServerKeys, identity_seed: bytes | None = None):
        seed = identity_seed or os.urandom(32)
        self.x_kp   = H.SUITE.kem.derive_key_pair(seed)               # static identity (§2)
        self.ed     = Ed25519PrivateKey.from_private_bytes(H.hashlib.sha256(b"ed" + seed).digest())
        self.x_pub  = self.x_kp.public_key.to_public_bytes()
        self.ed_pub = self.ed.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.pin_x, self.pin_ed = server_keys.x25519_pub_bytes, server_keys.ed25519_pub_bytes
        self.epochs: dict[bytes, object] = {}                           # epoch_id → epoch keypair
        self.reset()

    def reset(self):
        self.sender = self.recipient = self.session_id = self.t_hello = None
        self.c2s_seq, self.s2c_seq = 0, 0
        self.history = None

    # handshake (§4.2 / §4.3.1)
    def hello(self) -> str:
        enc, self.sender = H.SUITE.create_sender_context(
            H.SUITE.kem.deserialize_public_key(self.pin_x), info=H.HPKE_INFO)
        self.t_hello = H.build_t_hello(self.x_pub, self.ed_pub, enc, self.pin_x, self.pin_ed)
        return json.dumps({
            "type": "hello", "browser_x25519": H.b64url_encode(self.x_pub),
            "browser_ed25519": H.b64url_encode(self.ed_pub), "enc": H.b64url_encode(enc),
            "sig": H.b64url_encode(self.ed.sign(self.t_hello)),
        })

    def accept_server_hello(self, raw: str):
        f = json.loads(raw)
        assert f["type"] == "server_hello"
        enc, sig = H.b64url_decode(f["enc"]), H.b64url_decode(f["sig"])
        t = H.build_t_server_hello(enc, self.x_pub, self.ed_pub, self.pin_x, self.pin_ed)
        Ed25519PublicKey.from_public_bytes(self.pin_ed).verify(sig, t)
        self.session_id = H.compute_session_id(self.t_hello, t)
        self.recipient = H.SUITE.create_recipient_context(enc, self.x_kp.private_key, info=H.HPKE_INFO)

    # sealed frames (§7.2)
    def seal(self, wire_type: str, frame_type: bytes, pt: bytes, aad_type: bytes | None = None) -> str:
        aad = H.make_aad(H.DIR_C2S, self.session_id, self.c2s_seq, aad_type or frame_type)
        frame = {"type": wire_type, "seq": H.seq_to_hex(self.c2s_seq),
                 "ct": H.b64url_encode(self.sender.seal(pt, aad=aad))}
        self.c2s_seq += 1
        return json.dumps(frame)

    def open(self, raw: str, expect_type: str, frame_type: bytes) -> bytes:
        f = json.loads(raw)
        assert f["type"] == expect_type, f
        assert H.hex_to_seq(f["seq"]) == self.s2c_seq
        aad = H.make_aad(H.DIR_S2C, self.session_id, self.s2c_seq, frame_type)
        pt = self.recipient.open(H.b64url_decode(f["ct"]), aad=aad)
        self.s2c_seq += 1
        return pt

    # storage (§9)
    def storage_aad(self, epoch_id: bytes) -> bytes:
        return self.ed_pub + epoch_id                                   # §9.4

    def mint_epoch(self) -> tuple[bytes, str]:
        """New random epoch; returns (epoch_id, sealed epoch_key frame)."""
        epoch_id = os.urandom(16)
        kp = H.SUITE.kem.derive_key_pair(os.urandom(32))
        self.epochs[epoch_id] = kp
        enc, ct = hpke_seal(self.x_kp.public_key, kp.private_key.to_private_bytes(),
                              INFO_EPOCH_KEY, self.storage_aad(epoch_id))
        pt = json.dumps({"epoch": H.b64url_encode(epoch_id), "enc": H.b64url_encode(enc),
                         "ct": H.b64url_encode(ct)}).encode()
        return epoch_id, self.seal("epoch_key", H.TYPE_EPOCH_KEY, pt)

    def msg(self, text: str, epoch_id: bytes, **seal_kw) -> str:
        enc, ct = hpke_seal(self.epochs[epoch_id].public_key,
                              json.dumps({"text": text, "ts": 1}).encode(),
                              INFO_RECORD, self.storage_aad(epoch_id))
        pt = json.dumps({"text": text, "rec": {"epoch": H.b64url_encode(epoch_id),
                                               "enc": H.b64url_encode(enc), "ct": H.b64url_encode(ct)}}).encode()
        return self.seal("msg", H.TYPE_MSG, pt, **seal_kw)

    def accept_history(self, raw: str) -> dict:
        h = json.loads(self.open(raw, "history", H.TYPE_HISTORY))
        for e in h["epochs"]:                                           # recover epoch keys (§9.2)
            epoch_id = H.b64url_decode(e["epoch"])
            sk = hpke_open(H.b64url_decode(e["enc"]), self.x_kp.private_key, H.b64url_decode(e["ct"]),
                           INFO_EPOCH_KEY, self.storage_aad(epoch_id))
            self.epochs[epoch_id] = _kp_from_scalar(sk)
        self.history = h
        return h

    def restored_texts(self) -> list[str]:
        out = []
        for r in self.history["records"]:                               # open records (§9.3)
            epoch_id = H.b64url_decode(r["epoch"])
            pt = hpke_open(H.b64url_decode(r["enc"]), self.epochs[epoch_id].private_key,
                           H.b64url_decode(r["ct"]), INFO_RECORD, self.storage_aad(epoch_id))
            out.append(json.loads(pt)["text"])
        return out


def _kp_from_scalar(sk: bytes):
    priv = H.SUITE.kem.deserialize_private_key(sk)
    pub  = H.SUITE.kem.deserialize_public_key(
        priv.raw.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    return H.KEMKeyPair(sk=priv, pk=pub)


# ── Harness: drive serve_secure_link with queues instead of a socket ─────────

class Link:
    def __init__(self, keys, history):
        self.to_server: asyncio.Queue = asyncio.Queue()
        self.to_client: asyncio.Queue = asyncio.Queue()
        self.task = asyncio.create_task(serve_secure_link(self.to_server.get, self.to_client.put, keys, history))

    async def send(self, raw: str):
        await self.to_server.put(raw)

    async def recv(self, timeout=2.0) -> str:
        getter = asyncio.create_task(self.to_client.get())
        done, _ = await asyncio.wait({getter, self.task}, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
        if getter in done:
            return getter.result()
        getter.cancel()
        self.task.result()                       # raises the ProtocolError the server hit
        raise AssertionError("server loop ended without a frame")

    async def expect_fault(self, timeout=2.0) -> H.ProtocolError:
        with pytest.raises(H.ProtocolError) as ei:
            await asyncio.wait_for(self.task, timeout)
        return ei.value

    def close(self):
        self.task.cancel()


@pytest.fixture
def server_keys(monkeypatch):
    g = H.generate_server_keys()
    monkeypatch.setenv("SERVER_X25519_PRIVATE_KEY_HEX", g["SERVER_X25519_PRIVATE_KEY_HEX"])
    monkeypatch.setenv("SERVER_ED25519_PRIVATE_KEY_HEX", g["SERVER_ED25519_PRIVATE_KEY_HEX"])
    return H.load_server_keys()


@pytest.fixture
def history(tmp_path):
    svc = HistoryService(EpochKeyStore(str(tmp_path / "e.sqlite3")), MemoryRecordStore(),
                         Policy(epoch_length_s=3600, window_s=7 * 86400, max_records=500))
    yield svc
    svc.close()


async def connect(browser: PyBrowser, keys, history) -> tuple[Link, dict]:
    """hello → server_hello → history; returns the link ESTABLISHED and the history plaintext."""
    browser.reset()
    link = Link(keys, history)
    await link.send(browser.hello())
    browser.accept_server_hello(await link.recv())
    h = browser.accept_history(await link.recv())
    return link, h


# ── Tests ────────────────────────────────────────────────────────────────────

def test_roundtrip_then_recover_with_same_identity(server_keys, history):
    async def go():
        seed = os.urandom(32)
        b = PyBrowser(server_keys, seed)
        link, h = await connect(b, server_keys, history)
        assert h == {"policy": {"epoch_length_s": 3600, "window_s": 604800}, "epochs": [], "records": []}
        assert b.s2c_seq == 1                                  # history consumed s2c seq 0

        epoch_id, frame = b.mint_epoch()
        await link.send(frame)                                 # epoch_key: no reply expected
        await link.send(b.msg("My fake SSN is 123-45-6789", epoch_id))
        echo = b.open(await link.recv(), "msg", H.TYPE_MSG)
        assert echo == b"ECHO: My fake SSN is 123-45-6789"    # s2c seq 1
        await link.send(b.msg("second", epoch_id))
        assert b.open(await link.recv(), "msg", H.TYPE_MSG) == b"ECHO: second"
        link.close()

        # A fresh browser with the SAME words gets everything back (D021).
        again = PyBrowser(server_keys, seed)
        link2, h2 = await connect(again, server_keys, history)
        assert len(h2["epochs"]) == 1 and h2["epochs"][0]["epoch"] == H.b64url_encode(epoch_id)
        assert again.restored_texts() == ["My fake SSN is 123-45-6789", "second"]
        link2.close()

        # A different identity sees nothing (per-user isolation is free).
        other = PyBrowser(server_keys)
        link3, h3 = await connect(other, server_keys, history)
        assert h3["epochs"] == [] and h3["records"] == []
        link3.close()
    asyncio.run(go())


def test_record_for_unknown_epoch_tears_down(server_keys, history):
    async def go():
        b = PyBrowser(server_keys)
        link, _ = await connect(b, server_keys, history)
        epoch_id = os.urandom(16)
        b.epochs[epoch_id] = H.SUITE.kem.derive_key_pair(os.urandom(32))   # minted but never uploaded
        await link.send(b.msg("orphan", epoch_id))
        assert "unknown epoch" in str(await link.expect_fault())
    asyncio.run(go())


def test_repeated_epoch_id_tears_down(server_keys, history):
    async def go():
        b = PyBrowser(server_keys)
        link, _ = await connect(b, server_keys, history)
        epoch_id, frame = b.mint_epoch()
        await link.send(frame)
        # Re-seal the same epoch under a fresh seq (a replay would fail the seq gate first).
        kp = b.epochs[epoch_id]
        enc, ct = hpke_seal(b.x_kp.public_key, kp.private_key.to_private_bytes(),
                            INFO_EPOCH_KEY, b.storage_aad(epoch_id))
        pt = json.dumps({"epoch": H.b64url_encode(epoch_id), "enc": H.b64url_encode(enc),
                         "ct": H.b64url_encode(ct)}).encode()
        await link.send(b.seal("epoch_key", H.TYPE_EPOCH_KEY, pt))
        assert "repeated epoch" in str(await link.expect_fault())
    asyncio.run(go())


def test_frame_type_flip_fails_open(server_keys, history):
    """Sealed with TYPE=epoch_key but labelled msg → AAD mismatch → teardown (§3.0.1)."""
    async def go():
        b = PyBrowser(server_keys)
        link, _ = await connect(b, server_keys, history)
        epoch_id, frame = b.mint_epoch()
        await link.send(frame)
        await link.send(b.msg("flip", epoch_id, aad_type=H.TYPE_EPOCH_KEY))
        assert "open() failed" in str(await link.expect_fault())
    asyncio.run(go())


def test_bare_text_plaintext_is_a_fault(server_keys, history):
    """The old raw-text plaintext contract is gone: no text-only fallback (§7.5)."""
    async def go():
        b = PyBrowser(server_keys)
        link, _ = await connect(b, server_keys, history)
        await link.send(b.seal("msg", H.TYPE_MSG, b"just words"))
        assert "not UTF-8 JSON" in str(await link.expect_fault())
    asyncio.run(go())


def test_wrong_frame_types_per_phase(server_keys, history):
    async def go():
        b = PyBrowser(server_keys)
        link = Link(server_keys, history)
        await link.send(json.dumps({"type": "epoch_key", "seq": "0" * 16, "ct": "AA"}))
        assert "expected hello" in str(await link.expect_fault())

        link, _ = await connect(b, server_keys, history)
        await link.send(json.dumps({"type": "history", "seq": "0" * 16, "ct": "AA"}))
        assert "expected msg/epoch_key" in str(await link.expect_fault())
    asyncio.run(go())


def test_history_must_be_first_s2c_frame(server_keys):
    s = H.ServerSession(keys=server_keys)
    b = PyBrowser(server_keys)
    sh = s.handle_hello(json.loads(b.hello()))
    b.accept_server_hello(json.dumps(sh))
    s.seal_reply(b"ECHO: x")
    with pytest.raises(H.ProtocolError):
        s.seal_history({"policy": {}, "epochs": [], "records": []})


def test_expired_epoch_makes_records_unrecoverable(server_keys, tmp_path, monkeypatch):
    """After the window the sealed epoch key is erased: the browser never sees the records."""
    svc = HistoryService(EpochKeyStore(str(tmp_path / "e.sqlite3")), MemoryRecordStore(),
                         Policy(epoch_length_s=10, window_s=100, max_records=50))
    clock = {"now": 1_000}
    monkeypatch.setattr(HistoryService, "now", staticmethod(lambda: clock["now"]))

    async def go():
        seed = os.urandom(32)
        b = PyBrowser(server_keys, seed)
        link, _ = await connect(b, server_keys, svc)
        epoch_id, frame = b.mint_epoch()
        await link.send(frame)
        await link.send(b.msg("gone soon", epoch_id))
        b.open(await link.recv(), "msg", H.TYPE_MSG)
        link.close()

        clock["now"] = 1_099                                    # inside the window: still there
        again = PyBrowser(server_keys, seed)
        link2, h = await connect(again, server_keys, svc)
        assert again.restored_texts() == ["gone soon"]
        link2.close()

        clock["now"] = 1_100                                    # window elapsed: key erased
        later = PyBrowser(server_keys, seed)
        link3, h = await connect(later, server_keys, svc)
        assert h["epochs"] == [] and h["records"] == []
        link3.close()
    asyncio.run(go())
    svc.close()
