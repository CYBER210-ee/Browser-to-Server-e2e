"""Storage layer (ADR 212 / protocol §9.5): epoch keys, records, sweeper, policy."""

import asyncio
import os

import pytest

from history_store import (
    EpochExists, EpochKeyStore, HistoryService, MemoryRecordStore, Policy,
    PostgresRecordStore, SealedEpochKey, StoredRecord, load_policy, parse_duration,
)

OWNER_A = b"\xaa" * 32
OWNER_B = b"\xbb" * 32
EPOCH_1 = b"\x01" * 16
EPOCH_2 = b"\x02" * 16


def key(epoch, created_at):
    return SealedEpochKey(epoch, b"e" * 32, b"c" * 48, created_at)


def rec(epoch, created_at, tag=b"r"):
    return StoredRecord(epoch, b"e" * 32, tag * 40, created_at)


# ── parse_duration / policy ──────────────────────────────────────────────────

@pytest.mark.parametrize("text,seconds", [
    ("30", 30), ("30s", 30), ("15m", 900), ("1h", 3600), ("7d", 604800), (" 12h ", 43200),
])
def test_parse_duration(text, seconds):
    assert parse_duration(text) == seconds


@pytest.mark.parametrize("text", ["", "1w", "h", "-5m", "1.5h"])
def test_parse_duration_rejects(text):
    with pytest.raises(ValueError):
        parse_duration(text)


def test_load_policy_defaults(monkeypatch):
    for k in ("EPOCH_LENGTH", "HISTORY_WINDOW", "HISTORY_MAX_RECORDS"):
        monkeypatch.delenv(k, raising=False)
    assert load_policy() == Policy(3600, 7 * 86400, 500)


def test_load_policy_rejects_epoch_longer_than_window(monkeypatch):
    monkeypatch.setenv("EPOCH_LENGTH", "30d")
    monkeypatch.setenv("HISTORY_WINDOW", "7d")
    with pytest.raises(RuntimeError):
        load_policy()


# ── EpochKeyStore ────────────────────────────────────────────────────────────

@pytest.fixture
def epochs(tmp_path):
    store = EpochKeyStore(str(tmp_path / "epochs.sqlite3"))
    yield store
    store.close()


def test_epoch_insert_live_ordering_and_isolation(epochs):
    epochs.insert(OWNER_A, key(EPOCH_2, 200))
    epochs.insert(OWNER_A, key(EPOCH_1, 100))
    epochs.insert(OWNER_B, key(EPOCH_1, 50))
    live = epochs.live(OWNER_A)
    assert [k.epoch_id for k in live] == [EPOCH_1, EPOCH_2]      # oldest first
    assert epochs.has(OWNER_A, EPOCH_1) and not epochs.has(OWNER_B, EPOCH_2)


def test_epoch_duplicate_id_is_rejected(epochs):
    epochs.insert(OWNER_A, key(EPOCH_1, 100))
    with pytest.raises(EpochExists):
        epochs.insert(OWNER_A, key(EPOCH_1, 999))
    # same id for a different owner is a different key
    epochs.insert(OWNER_B, key(EPOCH_1, 100))


def test_epoch_erase_expired_is_inclusive_at_window(epochs):
    epochs.insert(OWNER_A, key(EPOCH_1, 1000))
    epochs.insert(OWNER_A, key(EPOCH_2, 1001))
    erased = epochs.erase_expired(now=1000 + 604800, window_s=604800)
    assert erased == [(OWNER_A, EPOCH_1)]                            # exactly window old → gone
    assert [k.epoch_id for k in epochs.live(OWNER_A)] == [EPOCH_2]


@pytest.mark.parametrize("reopen", [False, True])                  # key still in the WAL / already in the main file
def test_epoch_erase_leaves_no_key_bytes_on_disk(tmp_path, reopen):
    """An erased sealed key is gone from the database file and the WAL, not just unlinked."""
    path = tmp_path / "epochs.sqlite3"
    store = EpochKeyStore(str(path))
    secret = b"sealed-epoch-key-must-not-survive-erasure-000000"   # 48 bytes, like ct
    store.insert(OWNER_A, SealedEpochKey(EPOCH_1, b"e" * 32, secret, 0))
    store.insert(OWNER_A, key(EPOCH_2, 10**9))                      # a live neighbour on the same page
    if reopen:
        store.close()                                               # last close checkpoints into the main file
        store = EpochKeyStore(str(path))
    assert store.erase_expired(now=100, window_s=100) == [(OWNER_A, EPOCH_1)]
    for f in (path, tmp_path / "epochs.sqlite3-wal"):               # read while the store is still open
        if f.exists():
            assert secret not in f.read_bytes(), f.name
    store.close()


def test_epoch_store_persists_across_reopen(tmp_path):
    path = str(tmp_path / "epochs.sqlite3")
    s = EpochKeyStore(path)
    s.insert(OWNER_A, key(EPOCH_1, 1))
    s.close()
    s = EpochKeyStore(path)
    assert s.has(OWNER_A, EPOCH_1)
    s.close()


# ── MemoryRecordStore ────────────────────────────────────────────────────────

def test_memory_records_recent_cap_and_delete():
    store = MemoryRecordStore()
    for i in range(5):
        store.insert("srv", OWNER_A, rec(EPOCH_1 if i < 3 else EPOCH_2, i, tag=bytes([i])))
    store.insert("srv", OWNER_B, rec(EPOCH_1, 99))
    newest3 = store.recent("srv", OWNER_A, 3)
    assert [r.created_at for r in newest3] == [2, 3, 4]              # oldest-first slice of the newest
    assert store.delete_epoch("srv", OWNER_A, EPOCH_1) == 3
    assert [r.created_at for r in store.recent("srv", OWNER_A, 10)] == [3, 4]
    assert len(store.recent("srv", OWNER_B, 10)) == 1


def test_records_are_per_server():
    """D031: a record filed with server A is invisible to, and undeletable by, server B."""
    store = MemoryRecordStore()
    store.insert("A", OWNER_A, rec(EPOCH_1, 1))
    assert store.recent("B", OWNER_A, 10) == []
    assert store.delete_epoch("B", OWNER_A, EPOCH_1) == 0
    assert len(store.recent("A", OWNER_A, 10)) == 1


# ── HistoryService ───────────────────────────────────────────────────────────

def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_service_sweep_erases_keys_and_cascades_records(epochs):
    records = MemoryRecordStore()
    svc = HistoryService(epochs, records, Policy(epoch_length_s=10, window_s=100, max_records=50))
    epochs.insert(OWNER_A, key(EPOCH_1, 0))
    epochs.insert(OWNER_A, key(EPOCH_2, 500))
    records.insert("echovault", OWNER_A, rec(EPOCH_1, 5))
    records.insert("echovault", OWNER_A, rec(EPOCH_2, 505))

    assert run(svc.sweep(now=99)) == 0
    assert run(svc.sweep(now=100)) == 1
    assert [k.epoch_id for k in epochs.live(OWNER_A)] == [EPOCH_2]
    assert [r.epoch_id for r in records.recent("echovault", OWNER_A, 10)] == [EPOCH_2]


def test_service_history_for_shape(epochs, monkeypatch):
    records = MemoryRecordStore()
    svc = HistoryService(epochs, records, Policy(epoch_length_s=60, window_s=600, max_records=2))
    monkeypatch.setattr(HistoryService, "now", staticmethod(lambda: 1000))
    run(svc.add_epoch_key(OWNER_A, EPOCH_1, b"e" * 32, b"c" * 48))
    for i in range(3):
        run(svc.add_record(OWNER_A, EPOCH_1, b"e" * 32, bytes([i]) * 40))

    h = run(svc.history_for(OWNER_A))
    assert h["policy"] == {"epoch_length_s": 60, "window_s": 600}
    assert len(h["epochs"]) == 1 and h["epochs"][0]["created_at"] == 1000
    assert set(h["epochs"][0]) == {"epoch", "created_at", "enc", "ct"}
    assert len(h["records"]) == 2                                     # capped at max_records, newest kept
    assert h["records"][-1]["ct"].startswith("AgIC")                  # b"\x02"*40 base64url
    assert run(svc.history_for(OWNER_B)) == {"policy": h["policy"], "epochs": [], "records": []}


def test_service_duplicate_epoch_raises(epochs):
    svc = HistoryService(epochs, MemoryRecordStore(), Policy())
    run(svc.add_epoch_key(OWNER_A, EPOCH_1, b"e" * 32, b"c" * 48))
    with pytest.raises(EpochExists):
        run(svc.add_epoch_key(OWNER_A, EPOCH_1, b"e" * 32, b"c" * 48))


# ── Postgres (only with a real database) ─────────────────────────────────────

def test_postgres_host_override_is_applied(monkeypatch):
    """DB_HOST swaps the DSN host (compose → `db`) before anything else is checked."""
    seen = {}
    def fake_connect(conninfo, autocommit=True):
        seen["conninfo"] = conninfo
        raise RuntimeError("stop here")
    monkeypatch.setattr("psycopg.connect", fake_connect)
    with pytest.raises(RuntimeError, match="stop here"):
        PostgresRecordStore("postgresql://u:p@localhost/db?sslmode=verify-full&sslrootcert=/x", host="db")
    assert "host=db" in seen["conninfo"] and "localhost" not in seen["conninfo"]


def test_postgres_refuses_without_verify_full():
    with pytest.raises(RuntimeError):
        PostgresRecordStore("postgresql://u:p@localhost/db?sslmode=require&sslrootcert=/x")
    with pytest.raises(RuntimeError):
        PostgresRecordStore("postgresql://u:p@localhost/db?sslmode=verify-full")


@pytest.mark.skipif(not os.environ.get("DATABASE_URL"), reason="DATABASE_URL not set")
def test_postgres_roundtrip():
    store = PostgresRecordStore(os.environ["DATABASE_URL"], os.environ.get("DB_SSLROOTCERT"))
    owner = os.urandom(32)
    for i in range(4):
        store.insert("test", owner, rec(EPOCH_1 if i < 2 else EPOCH_2, i, tag=bytes([i])))
    got = store.recent("test", owner, 3)
    assert [r.created_at for r in got] == [1, 2, 3]
    assert store.recent("other", owner, 3) == []                       # D031
    assert store.delete_epoch("test", owner, EPOCH_1) == 2
    assert store.delete_epoch("test", owner, EPOCH_2) == 2
