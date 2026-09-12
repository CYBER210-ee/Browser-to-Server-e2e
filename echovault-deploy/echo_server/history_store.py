"""
history_store.py — stored-history persistence for EchoVault (ADR 212, protocol §9)

Two stores behind one small interface (D024):
  EpochKeyStore   — sealed epoch private keys, SQLite on the server host
  RecordStore     — sealed prompt records, Postgres over TLS (or in-memory, dev/tests)

The server never opens either blob — it files them under the owner proven by the
hello signature and hands them back in the history push (D021). Expiry is the
sweeper ERASING a sealed epoch key once it is older than HISTORY_WINDOW; the
epoch's records are deleted as hygiene, but the guarantee is the key (D022).

Key decisions:
  D021 — server and database hold opaque blobs only
  D022 — random epoch keys; expiry = key erasure after HISTORY_WINDOW
  D024 — keys on the server host, records in a remote Postgres over verify-full TLS
"""

from __future__ import annotations

import asyncio
import os
import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Protocol

# ── Retention policy (§9.5) ───────────────────────────────────────────────────

_DURATION = re.compile(r"^\s*(\d+)\s*([smhd])?\s*$")
_UNIT_SECONDS = {None: 1, "s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration(text: str) -> int:
    """'90', '30s', '15m', '1h', '7d' → seconds. Raises ValueError on anything else."""
    m = _DURATION.match(str(text))
    if not m:
        raise ValueError(f"bad duration {text!r}: expected <int>[s|m|h|d]")
    return int(m.group(1)) * _UNIT_SECONDS[m.group(2)]


@dataclass(frozen=True)
class Policy:
    """Retention settings; sent to the browser in the history push (§5.4.2)."""
    epoch_length_s: int = 3600       # EPOCH_LENGTH    default 1h
    window_s:       int = 7 * 86400  # HISTORY_WINDOW  default 7d
    max_records:    int = 500        # HISTORY_MAX_RECORDS

    def as_wire(self) -> dict:
        return {"epoch_length_s": self.epoch_length_s, "window_s": self.window_s}


def load_policy() -> Policy:
    """Read EPOCH_LENGTH / HISTORY_WINDOW / HISTORY_MAX_RECORDS from the environment."""
    epoch_len = parse_duration(os.environ.get("EPOCH_LENGTH", "1h"))
    window    = parse_duration(os.environ.get("HISTORY_WINDOW", "7d"))
    cap       = int(os.environ.get("HISTORY_MAX_RECORDS", "500"))
    if epoch_len <= 0 or window <= 0 or cap <= 0:
        raise RuntimeError("EPOCH_LENGTH, HISTORY_WINDOW and HISTORY_MAX_RECORDS must be positive")
    if epoch_len > window:
        # A record must be alive for at least window − epoch_length (§9.5); this
        # configuration would let a record expire before its epoch ends.
        raise RuntimeError("EPOCH_LENGTH must not exceed HISTORY_WINDOW")
    return Policy(epoch_length_s=epoch_len, window_s=window, max_records=cap)


# ── Blob shapes (§9) ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class SealedEpochKey:
    """{epoch_id, enc, ct} from an epoch_key frame (§5.4.1) + server created_at."""
    epoch_id:   bytes   # 16 raw
    enc:        bytes   # 32 raw
    ct:         bytes   # 48 raw (sealed 32-byte scalar ‖ tag)
    created_at: int     # UNIX seconds, server clock

    def as_wire(self) -> dict:
        from hpke_server import b64url_encode
        return {
            "epoch":      b64url_encode(self.epoch_id),
            "created_at": self.created_at,
            "enc":        b64url_encode(self.enc),
            "ct":         b64url_encode(self.ct),
        }


@dataclass(frozen=True)
class StoredRecord:
    """`rec` from a c2s msg (§7.5) + server created_at."""
    epoch_id:   bytes   # 16 raw
    enc:        bytes   # 32 raw
    ct:         bytes   # sealed record JSON ‖ tag
    created_at: int

    as_wire = SealedEpochKey.as_wire


class EpochExists(Exception):
    """A repeated epoch_id for the same owner — replay or client bug; caller tears down."""


# ── Epoch keys: SQLite on the server host (D024) ──────────────────────────────

class EpochKeyStore:
    """
    Sealed epoch private keys, keyed by (owner, epoch_id). Lives on the box the
    operator controls so that erasing a row here is what makes history expire.
    Synchronous; HistoryService wraps calls in a worker thread.
    """

    def __init__(self, path: str):
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS epoch_keys ("
            "  owner BLOB NOT NULL, epoch_id BLOB NOT NULL,"
            "  enc BLOB NOT NULL, ct BLOB NOT NULL, created_at INTEGER NOT NULL,"
            "  PRIMARY KEY (owner, epoch_id))"
        )

    def insert(self, owner: bytes, key: SealedEpochKey) -> None:
        with self._lock:
            try:
                self._db.execute(
                    "INSERT INTO epoch_keys (owner, epoch_id, enc, ct, created_at) VALUES (?,?,?,?,?)",
                    (owner, key.epoch_id, key.enc, key.ct, key.created_at),
                )
            except sqlite3.IntegrityError as e:
                raise EpochExists(key.epoch_id.hex()) from e

    def has(self, owner: bytes, epoch_id: bytes) -> bool:
        with self._lock:
            row = self._db.execute(
                "SELECT 1 FROM epoch_keys WHERE owner=? AND epoch_id=?", (owner, epoch_id)
            ).fetchone()
        return row is not None

    def live(self, owner: bytes) -> list[SealedEpochKey]:
        """All of this owner's sealed keys, oldest first (expired ones are already gone)."""
        with self._lock:
            rows = self._db.execute(
                "SELECT epoch_id, enc, ct, created_at FROM epoch_keys WHERE owner=? "
                "ORDER BY created_at, epoch_id", (owner,)
            ).fetchall()
        return [SealedEpochKey(bytes(r[0]), bytes(r[1]), bytes(r[2]), int(r[3])) for r in rows]

    def erase_expired(self, now: int, window_s: int) -> list[tuple[bytes, bytes]]:
        """ERASE every key with now − created_at ≥ window_s. Returns the (owner, epoch_id) pairs erased."""
        cutoff = now - window_s
        with self._lock:
            rows = self._db.execute(
                "SELECT owner, epoch_id FROM epoch_keys WHERE created_at <= ?", (cutoff,)
            ).fetchall()
            self._db.execute("DELETE FROM epoch_keys WHERE created_at <= ?", (cutoff,))
        return [(bytes(r[0]), bytes(r[1])) for r in rows]

    def close(self) -> None:
        with self._lock:
            self._db.close()


# ── Records: interface + implementations ─────────────────────────────────────

class RecordStore(Protocol):
    def insert(self, owner: bytes, rec: StoredRecord) -> None: ...
    def recent(self, owner: bytes, limit: int) -> list[StoredRecord]:
        """Up to `limit` newest records, returned oldest first (§5.4.2)."""
        ...
    def delete_epoch(self, owner: bytes, epoch_id: bytes) -> int: ...
    def close(self) -> None: ...


class MemoryRecordStore:
    """Non-persistent store for tests and HISTORY_BACKEND=memory dev runs. Same blobs, no disk."""

    def __init__(self):
        self._rows: list[tuple[bytes, StoredRecord]] = []
        self._lock = threading.Lock()

    def insert(self, owner: bytes, rec: StoredRecord) -> None:
        with self._lock:
            self._rows.append((owner, rec))

    def recent(self, owner: bytes, limit: int) -> list[StoredRecord]:
        with self._lock:
            mine = [r for o, r in self._rows if o == owner]
        return mine[-limit:] if limit > 0 else []

    def delete_epoch(self, owner: bytes, epoch_id: bytes) -> int:
        with self._lock:
            before = len(self._rows)
            self._rows = [(o, r) for o, r in self._rows if not (o == owner and r.epoch_id == epoch_id)]
            return before - len(self._rows)

    def close(self) -> None:
        pass


class PostgresRecordStore:
    """
    Sealed records in a Postgres that may live anywhere. Every call opens its own
    autocommit connection (no pool dependency; the link is TLS so setup is the
    cost we pay per call — fine at demo volume).

    The DSN MUST carry sslmode=verify-full (fail closed at construction); the CA
    can come from the DSN's sslrootcert or from DB_SSLROOTCERT.
    """

    def __init__(self, dsn: str, sslrootcert: str | None = None):
        import psycopg
        from psycopg import conninfo
        params = conninfo.conninfo_to_dict(dsn)
        if sslrootcert and "sslrootcert" not in params:
            params["sslrootcert"] = sslrootcert
        if params.get("sslmode") != "verify-full":
            raise RuntimeError("DATABASE_URL must set sslmode=verify-full (D024)")
        if not params.get("sslrootcert"):
            raise RuntimeError("DATABASE_URL needs sslrootcert=<ca.crt> (or set DB_SSLROOTCERT)")
        self._psycopg = psycopg
        self._conninfo = conninfo.make_conninfo(**params)
        with self._connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS history_records ("
                "  id BIGSERIAL PRIMARY KEY, owner BYTEA NOT NULL, epoch_id BYTEA NOT NULL,"
                "  enc BYTEA NOT NULL, ct BYTEA NOT NULL, created_at BIGINT NOT NULL)"
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS history_records_owner_idx ON history_records (owner, id)"
            )

    def _connect(self):
        return self._psycopg.connect(self._conninfo, autocommit=True)

    def insert(self, owner: bytes, rec: StoredRecord) -> None:
        with self._connect() as db:
            db.execute(
                "INSERT INTO history_records (owner, epoch_id, enc, ct, created_at) VALUES (%s,%s,%s,%s,%s)",
                (owner, rec.epoch_id, rec.enc, rec.ct, rec.created_at),
            )

    def recent(self, owner: bytes, limit: int) -> list[StoredRecord]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT epoch_id, enc, ct, created_at FROM ("
                "  SELECT id, epoch_id, enc, ct, created_at FROM history_records"
                "  WHERE owner=%s ORDER BY id DESC LIMIT %s) newest ORDER BY id ASC",
                (owner, limit),
            ).fetchall()
        return [StoredRecord(bytes(r[0]), bytes(r[1]), bytes(r[2]), int(r[3])) for r in rows]

    def delete_epoch(self, owner: bytes, epoch_id: bytes) -> int:
        with self._connect() as db:
            cur = db.execute(
                "DELETE FROM history_records WHERE owner=%s AND epoch_id=%s", (owner, epoch_id)
            )
            return cur.rowcount

    def close(self) -> None:
        pass


# ── Service: what main.py talks to ───────────────────────────────────────────

class HistoryService:
    """
    Async façade over the two sync stores. Store calls run in a worker thread so
    a slow remote Postgres never stalls the WebSocket loop.
    """

    def __init__(self, epochs: EpochKeyStore, records: RecordStore, policy: Policy):
        self.epochs  = epochs
        self.records = records
        self.policy  = policy

    @staticmethod
    def now() -> int:
        return int(time.time())

    async def sweep(self, now: int | None = None) -> int:
        """Erase expired epoch keys, then drop their records. Returns keys erased."""
        now = self.now() if now is None else now
        erased = await asyncio.to_thread(self.epochs.erase_expired, now, self.policy.window_s)
        for owner, epoch_id in erased:
            await asyncio.to_thread(self.records.delete_epoch, owner, epoch_id)
        return len(erased)

    async def add_epoch_key(self, owner: bytes, epoch_id: bytes, enc: bytes, ct: bytes) -> None:
        key = SealedEpochKey(epoch_id, enc, ct, self.now())
        await asyncio.to_thread(self.epochs.insert, owner, key)

    async def has_epoch(self, owner: bytes, epoch_id: bytes) -> bool:
        return await asyncio.to_thread(self.epochs.has, owner, epoch_id)

    async def add_record(self, owner: bytes, epoch_id: bytes, enc: bytes, ct: bytes) -> None:
        rec = StoredRecord(epoch_id, enc, ct, self.now())
        await asyncio.to_thread(self.records.insert, owner, rec)

    async def history_for(self, owner: bytes) -> dict:
        """The history-push plaintext (§5.4.2): policy + live epochs + recent records."""
        await self.sweep()
        epochs  = await asyncio.to_thread(self.epochs.live, owner)
        records = await asyncio.to_thread(self.records.recent, owner, self.policy.max_records)
        return {
            "policy":  self.policy.as_wire(),
            "epochs":  [e.as_wire() for e in epochs],
            "records": [r.as_wire() for r in records],
        }

    async def run_sweeper(self, interval_s: int = 60) -> None:
        """Background task: erase on a timer as well as on every connection."""
        while True:
            try:
                await self.sweep()
            except Exception as e:  # keep sweeping; never take the server down
                print(f"[history] sweep failed: {type(e).__name__}")
            await asyncio.sleep(interval_s)

    def close(self) -> None:
        self.epochs.close()
        self.records.close()


def open_history_service() -> HistoryService:
    """
    Build the service from the environment:
      EPOCH_DB_PATH     SQLite file for sealed epoch keys (default ./epoch_keys.sqlite3)
      HISTORY_BACKEND   'postgres' (default) or 'memory' (dev only — nothing persists)
      DATABASE_URL      postgresql://…?sslmode=verify-full&sslrootcert=… (postgres backend)
      DB_SSLROOTCERT    CA path if not in DATABASE_URL
    """
    policy  = load_policy()
    epochs  = EpochKeyStore(os.environ.get("EPOCH_DB_PATH", "./epoch_keys.sqlite3"))
    backend = os.environ.get("HISTORY_BACKEND", "postgres").strip().lower()
    if backend == "memory":
        print("[history] HISTORY_BACKEND=memory — records are NOT persisted (dev only)")
        records: RecordStore = MemoryRecordStore()
    elif backend == "postgres":
        dsn = os.environ.get("DATABASE_URL", "").strip()
        if not dsn:
            raise RuntimeError("DATABASE_URL not set (or HISTORY_BACKEND=memory for a dev run)")
        records = PostgresRecordStore(dsn, os.environ.get("DB_SSLROOTCERT") or None)
    else:
        raise RuntimeError(f"unknown HISTORY_BACKEND {backend!r}")
    return HistoryService(epochs, records, policy)
