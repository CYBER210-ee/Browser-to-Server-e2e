# ADR 2 — Per-connection channel forward secrecy

Branch: `212/channel_fs` (on top of `212/epoch_expiry`) · Status: implemented on branch 212/channel_fs (stacked on 212/epoch_expiry), awaiting push + manual review · Previous: ADR 212 epoch expiry · Next: ADR 3 retire `echovault-deploy/`

## Goal

A recording of the wire must become unrecoverable the moment the connection closes, even
if either side's long-term identity key is stolen later. Together with ADR 212's key
erasure this completes the claim: after the history window, neither the stored copy nor
a captured copy of a prompt can be recovered by anyone.

## Design summary

- **Both HPKE recipient keys become per-connection ephemeral X25519 keypairs.** Each side
  mints one at connection start, signs it with its Ed25519 identity, and wipes it at
  teardown. The static X25519 identity key stays in the §2 key tree but leaves the channel:
  its only job is now sealing epoch keys for stored history (ADR 212, §9.2).
- **The handshake gains one server-first frame.** The browser cannot seal to a key it has
  not seen, so on WebSocket open the server sends a signed `server_key` carrying its
  ephemeral public key. Then `hello` and `server_hello` proceed as today with ephemeral
  keys in place of static ones, every transcript covering the new material.
- **`SESSION_ID` covers all three transcripts.** `SHA-256(T_server_key ‖ T_hello ‖
  T_server_hello)[:16]`. Everything else in the AAD is unchanged.
- **Transcript labels bump to `v2`** because their contents changed meaning (`pubkey`
  shrinks; `hello`/`server_hello` carry ephemerals). A v1 signature can never be replayed
  into a v2 handshake.
- **`/pubkey` carries only the Ed25519 pin confirmation** (`server_ed25519`, `sig`). No
  X25519 field, no backward compatibility.
- **Acceptance gates stay and tighten** (§4.1.1, §4.3.1): the browser checks
  `server_key` against the pin *before* minting anything; `server_hello` must echo the
  browser's own ephemeral and the server ephemeral it already accepted.
- **Forward-secrecy claim.** Theft of either static identity key after a session ends
  reveals nothing from that session. It still allows impersonation going forward, the
  accepted limit of any signature-based identity. D009 and the threat model are corrected.

## Out of scope

Mid-session rotation (epoch/rekey frames) · interop harness (declined) · plaintext mode ·
the proxy · the deploy directory (ADR 3).

## Checklist

### 1. Docs first, then re-freeze
- [x] D026–D028 in `docs/decisions.md` (ephemeral recipient keys · server-first `server_key`
      frame + `v2` labels · `/pubkey` trimmed; D009 corrected)
- [x] `docs/protocol.md`: §0 labels and `SESSION_ID`, §2 (static X25519 = storage only),
      §3.0, §4 transcripts incl. new §4.0 `server_key`, §5.1–§5.3 shapes, §5.6 phases,
      §7.1 setup, §8, §9.6
- [x] `docs/threat-model.md`: forward secrecy now holds for the channel; wire-recording
      limitation removed; L2/L3 rows; key-management limitation rewritten

### 2. Server (`server/hpke_server.py`, `server/secure_link.py`, `server/main.py`)
- [x] Per-session ephemeral X25519 keypair; `server_key` frame + `T_server_key`
- [x] `v2` labels; `T_hello` / `T_server_hello` over ephemerals; server gate checks its own
      ephemeral in `hello`
- [x] `SESSION_ID` over three transcripts
- [x] `/pubkey` without `server_x25519`; `T_pubkey` v2
- [x] Ephemeral private key dropped at session end
- [x] Mirror into `echovault-deploy/echo_server/`

### 3. Client (`client/app/page.tsx`)
- [x] Verify: `/pubkey` v2 (Ed25519 pin only)
- [x] `AWAIT_SERVER_KEY` phase: verify `server_key` with the pin, mint the browser
      ephemeral, then send `hello`
- [x] `server_hello` gate against own ephemeral + accepted server ephemeral
- [x] Ephemeral scalar zeroed on teardown; static X25519 used only for storage seals

### 4. Tests
- [x] `PyBrowser` speaks the new handshake; existing history tests still pass
- [x] Gates: bad `server_key` sig / wrong pin key · `hello` sealed to a wrong server
      ephemeral · `server_hello` with a swapped browser ephemeral
- [x] Two connections → different `enc`s and `SESSION_ID`s
- [x] Forward secrecy: a captured c2s `ct` does not open with the server's static key
- [x] `npm run lint` / `npm run build`

### 5. Delivery
- [ ] Local commits ready; user pushes and opens the PR

## Dependencies

None new.
