# ADR 212 — Mnemonic-owned chat history with epoch expiry

Branch: `212/epoch_expiry` · Status: implemented on branch 212/epoch_expiry, awaiting push + manual review · Next ADR: per-connection channel forward secrecy

## Goal

Chat history survives across sessions and is recoverable from the BIP-39 mnemonic alone.
The server and the database hold only opaque blobs. Messages become unrecoverable after a
configurable window, Signal-style, by erasing a key rather than trusting every copy of the
data to be deleted.

## Design summary

- **Epoch keys are random X25519 keypairs minted in the browser**, one per `EPOCH_LENGTH`.
  Never derived from the mnemonic (a mnemonic-derived key can be re-derived forever and so
  can never expire). Each prompt is HPKE-sealed to the current epoch public key in the page.
- **Each epoch private key is HPKE-sealed to the static X25519 identity key** and uploaded
  once in a new sealed c2s `epoch_key` frame (TYPE `0x04`). Any browser holding the words can
  open it; the server cannot.
- **Sealed epoch keys live on the server host** (SQLite on a volume). **Record blobs live in
  remote Postgres over TLS** (`sslmode=verify-full`). Nothing in the remote location can
  decrypt itself, including backups.
- **Expiry = the server erasing the sealed epoch key** once the epoch is older than
  `HISTORY_WINDOW`. Sweeper runs on every connection and on a timer. Defaults: epoch 1h,
  window 7d. Both come from the server `.env`; the server sends the policy to the browser.
- **The sealed `msg` plaintext becomes structured**: `{ text, epoch, rec }`. One seal, one
  frame, no re-upload. Server echoes `text`, stores `rec` under the owner (the browser
  Ed25519 key proven by the `hello` signature). Record AAD binds owner and epoch.
- **New s2c `history` frame** (TYPE `0x05`) sent once right after `server_hello` with the
  policy, live sealed epoch keys, and records (newest last, capped). Must arrive, even empty,
  before the channel is ESTABLISHED. Browser reuses the current epoch key if one is live,
  otherwise mints one.
- **Echoes are not stored.** The browser rebuilds `ECHO: <text>` on replay and labels it
  restored.

## Out of scope

Plaintext mode (`/ws/plain`) in any form · deletion UI · pagination · any server-side key ·
mitmproxy (folder left untouched) · channel forward secrecy (next ADR).

## Limitations to record

- Expiry depends on the server erasing epoch keys on schedule.
- The server still sees each prompt live (D005), unchanged.
- An epoch private key sits in browser memory for the length of a session.
- A wire recording stays recoverable via the server static key until the next ADR lands.

## Checklist

### 1. Docs first, then re-freeze
- [x] D021–D025 in `docs/decisions.md` (ownership model · random epoch keys + erasure =
      expiry · structured msg plaintext + `epoch_key` / `history` frames · split stores ·
      echoes reconstructed)
- [x] `docs/protocol.md`: §3.0.1 TYPE table (`0x04`, `0x05`), §5 new frame shapes, §5.6 state
      machine rows, §7 plaintext contract, storage HPKE info strings and record AAD
- [x] `docs/threat-model.md`: stored history as a protected asset; the limitations above

### 2. Server storage module (`server/history_store.py`)
- [x] Epoch key store on SQLite (stdlib) — insert, list live, erase expired
- [x] Record store on Postgres via psycopg, TLS `verify-full` with the DB CA
- [x] Sweeper (on connect + timer) and policy loading (`EPOCH_LENGTH`, `HISTORY_WINDOW`,
      `DATABASE_URL`, `DB_CA_PATH`, `EPOCH_DB_PATH`)

### 3. Server protocol (`server/hpke_server.py`, `server/main.py`)
- [x] Session tracks owner from `hello`
- [x] `TYPE_EPOCH_KEY = 0x04`, `TYPE_HISTORY = 0x05`; AAD builder takes a type
- [x] Handle `epoch_key` frame in ESTABLISHED; reject records for unknown epochs
- [x] Parse structured `msg` plaintext, echo `text`, store `rec`
- [x] Push `history` frame right after `server_hello` (s2c seq 0)
- [x] Mirror server files (incl. new `secure_link.py`, `history_store.py`) into `echovault-deploy/echo_server/`

### 4. Client (`client/app/page.tsx`)
- [x] Epoch keypair minting, sealing epoch private key to the identity key, `epoch_key` upload
- [x] Seal each prompt to the epoch public key; send structured plaintext
- [x] `AWAIT_HISTORY` state; open epoch keys, open records, render restored messages and
      reconstructed echoes above the live transcript
- [x] Wipe epoch keys and history state on teardown

### 5. Database container and deploy
- [x] `echovault-deploy/echo_db/`: Postgres compose, TLS-only config + scram, cert generation
      script, `init.sql`
- [x] Server Dockerfile/compose carry the DB CA cert and new `.env` values; SQLite volume
- [x] Three-service compose (client, server, db), no proxy
- [x] README setup section replaced with build/run instructions (local dev + compose)

### 6. Tests and checks
- [x] pytest: epoch key store + sweeper expiry; record store (Postgres only when
      `DATABASE_URL` is set, fake otherwise)
- [x] pytest: full handshake + `history` push + `epoch_key` + structured `msg` with a
      Python-side browser (pyhpke both sides); fail-closed gates
- [x] `npm run lint` and `npm run build` in `client/`

### 7. Delivery
- [ ] Initial PR opened for manual review; follow-up PRs for fixes

## Dependencies (approved)

`psycopg[binary]`, `pytest` (server). SQLite is standard library. Nothing new on the client.
