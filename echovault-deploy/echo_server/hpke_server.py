"""
hpke_server.py — HPKE + Ed25519 crypto core for EchoVault (protocol v1, frozen)

Protocol: docs/protocol.md
Suite: DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305

Key decisions:
  D003 — ChaCha20-Poly1305
  D013 — frozen protocol constants (HPKE info, transcript labels, direction tokens)
  D014 — HPKE owns nonce/counter; no manual nonce handling
  D019 — seq gate: expected_next_seq tracked per direction; teardown on any fault
  D020 — TYPE byte (0x01) bound into AAD; strict state machine (§5.6)
  D023 — sealed epoch_key (0x04, c2s) / history (0x05, s2c) frames share the
         per-direction seq; c2s msg plaintext is the structured {text, rec} (§7.5)
  D026 — per-connection ephemeral recipient keys both ways; wiped at teardown
  D027 — server-first server_key frame; v2 transcript labels; SESSION_ID over 3 transcripts
  D028 — /pubkey carries the Ed25519 pin confirmation only
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
)
from pyhpke import CipherSuite, KEMId, KDFId, AEADId, KEMKeyPair

# ── Suite ─────────────────────────────────────────────────────────────────────

SUITE = CipherSuite.new(
    kem_id=KEMId.DHKEM_X25519_HKDF_SHA256,
    kdf_id=KDFId.HKDF_SHA256,
    aead_id=AEADId.CHACHA20_POLY1305,
)

# ── Frozen protocol constants (§0, §3, §4) ────────────────────────────────────

HPKE_INFO          = b"echovault/hpke/v1"           # §0 item 5, §7.1
STATE              = b"echovault"                    # §3.1
DIR_C2S            = b"c2s"                          # §0 item 4
DIR_S2C            = b"s2c"                          # §0 item 4
TYPE_MSG           = b"\x01"                         # §3.0.1
TYPE_EPOCH_KEY     = b"\x04"                         # §3.0.1 — c2s only (D023)
TYPE_HISTORY       = b"\x05"                         # §3.0.1 — s2c only (D023)

LABEL_SERVER_KEY   = b"echovault/server_key/v1"     # §4.0 — 23 bytes
LABEL_PUBKEY       = b"echovault/pubkey/v2"          # §4.1 — 19 bytes
LABEL_HELLO        = b"echovault/hello/v2"           # §4.2 — 18 bytes
LABEL_SERVER_HELLO = b"echovault/server_hello/v2"    # §4.3 — 25 bytes


class ProtocolError(Exception):
    """Any protocol violation — caller MUST tear down the connection."""


# ── Encoding helpers (§6) ─────────────────────────────────────────────────────

def b64url_encode(data: bytes) -> str:
    """base64url, no padding (§6)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    """base64url decode; re-pad missing = (§6)."""
    s = str(s)
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s)


def seq_to_hex(seq: int) -> str:
    """8-byte big-endian uint64 → 16-char lowercase hex (§5.4)."""
    return f"{seq:016x}"


def hex_to_seq(hex_str: str) -> int:
    return int(hex_str, 16)


def seq_to_bytes(seq: int) -> bytes:
    """I2OSP(seq, 8) for AAD (§3.1)."""
    return seq.to_bytes(8, "big")


# ── Transcript builders (§4) ──────────────────────────────────────────────────

def build_t_server_key(server_x25519: bytes, server_ed25519: bytes) -> bytes:
    """T_server_key = label(23) + server_x25519 EPHEMERAL(32) + server_ed25519(32) = 87 bytes (§4.0)."""
    return LABEL_SERVER_KEY + server_x25519 + server_ed25519


def build_t_pubkey(server_ed25519: bytes) -> bytes:
    """T_pubkey = label(19) + server_ed25519(32) = 51 bytes (§4.1, D028)."""
    return LABEL_PUBKEY + server_ed25519


def build_t_hello(
    browser_x25519: bytes, browser_ed25519: bytes,
    enc: bytes,
    server_x25519: bytes, server_ed25519: bytes,
) -> bytes:
    """T_hello = label(18)+bx25519(32)+bed25519(32)+enc(32)+sx25519(32)+sed25519(32)=178 bytes (§4.2).
    Both x25519 values are the per-connection ephemerals (D026)."""
    return LABEL_HELLO + browser_x25519 + browser_ed25519 + enc + server_x25519 + server_ed25519


def build_t_server_hello(
    s2c_enc: bytes,
    browser_x25519: bytes, browser_ed25519: bytes,
    server_x25519: bytes, server_ed25519: bytes,
) -> bytes:
    """T_server_hello = label(25)+enc(32)+bx25519(32)+bed25519(32)+sx25519(32)+sed25519(32)=185 bytes (§4.3)."""
    return LABEL_SERVER_HELLO + s2c_enc + browser_x25519 + browser_ed25519 + server_x25519 + server_ed25519


def compute_session_id(t_server_key: bytes, t_hello: bytes, t_server_hello: bytes) -> bytes:
    """SESSION_ID = SHA-256(T_server_key ‖ T_hello ‖ T_server_hello)[:16] (§3.0, D027)."""
    return hashlib.sha256(t_server_key + t_hello + t_server_hello).digest()[:16]


# ── AAD construction (§3) ─────────────────────────────────────────────────────

def make_aad(direction: bytes, session_id: bytes, seq: int, frame_type: bytes = TYPE_MSG) -> bytes:
    """
    AAD = STATE(9) ‖ SESSION_ID(16) ‖ DIRECTION(3) ‖ TYPE(1) ‖ SEQ8(8) = 37 bytes (§3.1)
    Never transmitted — both sides reconstruct independently. TYPE is the code
    for the frame class expected in the current state (§3.0.1), never the wire string.
    """
    assert len(session_id) == 16, f"SESSION_ID must be 16 bytes, got {len(session_id)}"
    assert len(frame_type) == 1
    return STATE + session_id + direction + frame_type + seq_to_bytes(seq)


# ── Sealed-plaintext shapes for the history frames (§5.4.1, §7.5) ─────────────

EPOCH_ID_LEN = 16
ENC_LEN      = 32
EPOCH_CT_LEN = 48      # sealed 32-byte scalar ‖ 16-byte tag


def _field_bytes(obj: dict, name: str, length: int | None = None, min_length: int = 0) -> bytes:
    """base64url-decode obj[name] and enforce its length; any fault is a ProtocolError."""
    v = obj.get(name)
    if not isinstance(v, str) or not v:
        raise ProtocolError(f"missing field {name}")
    try:
        raw = b64url_decode(v)
    except Exception:
        raise ProtocolError(f"bad base64url in {name}")
    if length is not None and len(raw) != length:
        raise ProtocolError(f"bad length for {name}")
    if len(raw) < min_length:
        raise ProtocolError(f"bad length for {name}")
    return raw


def _json_object(pt: bytes) -> dict:
    try:
        obj = json.loads(pt.decode("utf-8"))
    except Exception:
        raise ProtocolError("sealed plaintext is not UTF-8 JSON")
    if not isinstance(obj, dict):
        raise ProtocolError("sealed plaintext is not a JSON object")
    return obj


def parse_msg_plaintext(pt: bytes) -> tuple[str, bytes, bytes, bytes]:
    """
    c2s msg plaintext (§7.5): {"text": str, "rec": {"epoch", "enc", "ct"}}.
    Returns (text, epoch_id, rec_enc, rec_ct). No text-only fallback — a bare
    string here is a fault, exactly like a plaintext frame on the wire.
    """
    obj  = _json_object(pt)
    text = obj.get("text")
    rec  = obj.get("rec")
    if not isinstance(text, str) or not isinstance(rec, dict):
        raise ProtocolError("msg plaintext is not {text, rec}")
    epoch_id = _field_bytes(rec, "epoch", EPOCH_ID_LEN)
    enc      = _field_bytes(rec, "enc", ENC_LEN)
    ct       = _field_bytes(rec, "ct", min_length=16)
    return text, epoch_id, enc, ct


def parse_epoch_key_plaintext(pt: bytes) -> tuple[bytes, bytes, bytes]:
    """epoch_key plaintext (§5.4.1): {"epoch", "enc", "ct"} → (epoch_id, enc, ct)."""
    obj = _json_object(pt)
    return (
        _field_bytes(obj, "epoch", EPOCH_ID_LEN),
        _field_bytes(obj, "enc", ENC_LEN),
        _field_bytes(obj, "ct", EPOCH_CT_LEN),
    )


# ── Server key management ─────────────────────────────────────────────────────

@dataclass
class ServerKeys:
    """
    The server's long-term identity — Ed25519 only (D028). Loaded once at startup.
    There is no static X25519 key any more: every connection mints its own (§4.0).
    """
    ed25519_priv:       Ed25519PrivateKey
    ed25519_pub_bytes:  bytes   # 32 raw bytes


def generate_server_keys() -> dict:
    """
    Generate a fresh server identity (Ed25519).
    Call only from generate_keys.py; never at server startup.
    """
    ed25519_priv     = Ed25519PrivateKey.generate()
    ed25519_seed     = ed25519_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    ed25519_pub_hex  = ed25519_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return {
        "SERVER_ED25519_PRIVATE_KEY_HEX": ed25519_seed.hex(),
        "ed25519_pub_hex": ed25519_pub_hex,
    }


def load_server_keys() -> ServerKeys:
    """
    Load the server identity from the environment. Raises clearly if missing.
      SERVER_ED25519_PRIVATE_KEY_HEX — 64 hex chars (Ed25519 seed)
    A leftover SERVER_X25519_PRIVATE_KEY_HEX (pre-D028 .env files) is ignored.
    """
    ed25519_hex = os.environ.get("SERVER_ED25519_PRIVATE_KEY_HEX", "").strip().strip('"').strip("'")
    if not ed25519_hex:
        raise RuntimeError("SERVER_ED25519_PRIVATE_KEY_HEX not set. Run generate_keys.py.")

    ed25519_priv      = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(ed25519_hex))
    ed25519_pub_bytes = ed25519_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return ServerKeys(ed25519_priv=ed25519_priv, ed25519_pub_bytes=ed25519_pub_bytes)


def mint_ephemeral() -> tuple[KEMKeyPair, bytes]:
    """A fresh per-connection X25519 recipient keypair (D026) + its raw public bytes."""
    kp = SUITE.kem.derive_key_pair(os.urandom(32))
    return kp, kp.public_key.to_public_bytes()


# ── Per-connection state machine (§5.6) ───────────────────────────────────────

@dataclass
class ServerSession:
    """
    Per-WebSocket state machine.
      (accept)     → server_key_frame() mints this connection's ephemeral, phase AWAIT_HELLO
      AWAIT_HELLO  → accepts only hello
      ESTABLISHED  → accepts msg and epoch_key (c2s); emits history once, then msg
    Any wrong frame type or auth/ordering fault → raises ProtocolError.
    Never reuse across connections; call wipe() when the socket goes away.
    """
    keys: ServerKeys
    phase: str = "SEND_SERVER_KEY"
    owner: bytes = field(default=b"", repr=False)   # browser_ed25519 from hello — files history (§9.4)

    _eph_kp:            KEMKeyPair | None = field(default=None, repr=False)  # this connection only (D026)
    _eph_pub:           bytes  = field(default=b"", repr=False)
    _t_server_key:      bytes  = field(default=b"", repr=False)
    _recipient_ctx_c2s: object = field(default=None, repr=False)
    _sender_ctx_s2c:    object = field(default=None, repr=False)
    _session_id:        bytes  = field(default=None, repr=False)
    _expected_c2s:      int    = 0
    _expected_s2c:      int    = 0

    def server_key_frame(self) -> dict:
        """
        Mint the per-connection ephemeral and build the signed server_key frame
        (§4.0, §5.1.1). MUST be the first frame on the socket.
        """
        if self.phase != "SEND_SERVER_KEY":
            raise ProtocolError(f"server_key in wrong phase: {self.phase}")
        self._eph_kp, self._eph_pub = mint_ephemeral()
        self._t_server_key = build_t_server_key(self._eph_pub, self.keys.ed25519_pub_bytes)
        sig = self.keys.ed25519_priv.sign(self._t_server_key)
        self.phase = "AWAIT_HELLO"
        return {
            "type":          "server_key",
            "server_x25519": b64url_encode(self._eph_pub),
            "sig":           b64url_encode(sig),
        }

    def handle_hello(self, frame: dict) -> dict:
        """
        Process hello frame (§5.2).
        1. Verify browser Ed25519 sig over T_hello.
        2. Confirm T_hello binds to THIS connection's ephemeral + our identity (§4.2 server gate).
        3. Set up both HPKE contexts (ours on the ephemeral, theirs on the browser ephemeral).
        4. Sign and return server_hello frame dict (§5.3); drop the ephemeral private key.
        Raises ProtocolError on any failure.
        """
        if self.phase != "AWAIT_HELLO":
            raise ProtocolError(f"hello received in wrong phase: {self.phase}")

        try:
            browser_x25519  = b64url_decode(frame["browser_x25519"])
            browser_ed25519 = b64url_decode(frame["browser_ed25519"])
            c2s_enc         = b64url_decode(frame["enc"])
            sig             = b64url_decode(frame["sig"])
        except (KeyError, Exception) as e:
            raise ProtocolError(f"malformed hello frame: {e}") from e

        # Reconstruct T_hello using THIS connection's ephemeral + our identity (§4.2
        # server gate): a hello sealed to any other key — an earlier connection's
        # ephemeral included — fails the signature check below.
        t_hello = build_t_hello(
            browser_x25519, browser_ed25519, c2s_enc,
            self._eph_pub, self.keys.ed25519_pub_bytes,
        )

        # Verify browser signature — also implicitly confirms browser sealed to us
        try:
            Ed25519PublicKey.from_public_bytes(browser_ed25519).verify(sig, t_hello)
        except Exception as e:
            raise ProtocolError(f"hello sig verification failed: {e}") from e

        # Set up c2s recipient context (browser→server) on the ephemeral
        try:
            self._recipient_ctx_c2s = SUITE.create_recipient_context(
                enc=c2s_enc, skr=self._eph_kp.private_key, info=HPKE_INFO,
            )
            # Set up s2c sender context (server→browser) to the browser ephemeral
            s2c_enc, self._sender_ctx_s2c = SUITE.create_sender_context(
                pkr=SUITE.kem.deserialize_public_key(browser_x25519), info=HPKE_INFO,
            )
        except Exception as e:
            raise ProtocolError("hello key material rejected") from e

        # Build and sign T_server_hello
        t_server_hello = build_t_server_hello(
            s2c_enc, browser_x25519, browser_ed25519,
            self._eph_pub, self.keys.ed25519_pub_bytes,
        )
        sh_sig = self.keys.ed25519_priv.sign(t_server_hello)

        # Compute SESSION_ID — all three transcripts now known (§3.0)
        self._session_id = compute_session_id(self._t_server_key, t_hello, t_server_hello)
        self.owner = browser_ed25519
        self.phase = "ESTABLISHED"
        # The contexts hold their own derived keys; the ephemeral KEM private key has
        # done its only job. Drop it now so nothing outlives the connection (§7.1).
        self._eph_kp = None

        return {
            "type": "server_hello",
            "enc":  b64url_encode(s2c_enc),
            "sig":  b64url_encode(sh_sig),
        }

    def wipe(self) -> None:
        """Forget every per-connection secret (D026). Safe to call more than once."""
        self._eph_kp = None
        self._recipient_ctx_c2s = None
        self._sender_ctx_s2c = None
        self._session_id = None
        self.phase = "CLOSED"

    def handle_msg(self, frame: dict) -> bytes:
        """Open an incoming msg (§5.4, §7.2): the c2s plaintext of §7.5, still unparsed."""
        return self._open_frame(frame, TYPE_MSG, "msg")

    def handle_epoch_key(self, frame: dict) -> tuple[bytes, bytes, bytes]:
        """Open an incoming epoch_key (§5.4.1) → (epoch_id, enc, ct) for the store."""
        return parse_epoch_key_plaintext(self._open_frame(frame, TYPE_EPOCH_KEY, "epoch_key"))

    def _open_frame(self, frame: dict, frame_type: bytes, label: str) -> bytes:
        """
        Open any sealed c2s frame. The AAD uses the TYPE for the class this frame
        routed as — a flipped wire type therefore fails open() (§5.6).
        seq gate enforced before open() — D019/§7.3.
        Raises ProtocolError on any fault; caller MUST tear down.
        """
        if self.phase != "ESTABLISHED":
            raise ProtocolError(f"{label} received in wrong phase: {self.phase}")

        # Issue 1 fix: validate seq format before parsing
        seq_hex = frame.get("seq", "")
        if not isinstance(seq_hex, str) or len(seq_hex) != 16:
            raise ProtocolError("invalid seq: must be 16-char hex string")
        try:
            seq = hex_to_seq(seq_hex)
        except ValueError:
            raise ProtocolError("invalid seq: non-hex characters")

        # Issue 2 fix: validate ct field before decoding
        ct_b64 = frame.get("ct", "")
        if not isinstance(ct_b64, str) or len(ct_b64) == 0:
            raise ProtocolError("invalid ct: missing or empty")
        try:
            ct = b64url_decode(ct_b64)
        except Exception:
            raise ProtocolError("invalid ct: malformed base64url encoding")

        # seq gate (D019): reject duplicate/rollback/gap
        if seq != self._expected_c2s:
            raise ProtocolError(
                f"seq gate: expected {self._expected_c2s:#018x}, got {seq:#018x}"
            )

        aad = make_aad(DIR_C2S, self._session_id, seq, frame_type)
        try:
            plaintext = self._recipient_ctx_c2s.open(ct, aad=aad)
        except Exception:
            raise ProtocolError(f"{label} open() failed")
        self._expected_c2s += 1
        return plaintext

    def seal_reply(self, plaintext: bytes) -> dict:
        """Seal a server→browser echo (§5.4, §7.2). Returns ready-to-send frame dict."""
        return self._seal_frame(plaintext, TYPE_MSG, "msg")

    def seal_history(self, history: dict) -> dict:
        """Seal the one-time history push (§5.4.2). MUST be the first s2c frame (seq 0)."""
        if self._expected_s2c != 0:
            raise ProtocolError("history must be the first s2c frame")
        pt = json.dumps(history, separators=(",", ":")).encode("utf-8")
        return self._seal_frame(pt, TYPE_HISTORY, "history")

    def _seal_frame(self, plaintext: bytes, frame_type: bytes, wire_type: str) -> dict:
        if self.phase != "ESTABLISHED":
            raise ProtocolError(f"seal {wire_type} called outside ESTABLISHED phase")

        seq = self._expected_s2c
        aad = make_aad(DIR_S2C, self._session_id, seq, frame_type)
        ct  = self._sender_ctx_s2c.seal(plaintext, aad=aad)
        self._expected_s2c += 1

        return {
            "type": wire_type,
            "seq":  seq_to_hex(seq),
            "ct":   b64url_encode(ct),
        }
