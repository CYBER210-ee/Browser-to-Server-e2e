# ADR 5 — Client fixes

Branch: `agent/cs212/client_fixes` (on top of `main`) · Status: fixes 1–2 implemented, awaiting push + manual review · Previous: ADR 4 cloud deployment (scoping)

## Goal

Small client changes that make the demo easier to run, each recorded with what it costs
the threat model.

## Fix 1 — Pre-fill the server pin from `/pubkey` (D032)

Every rebuild or redeploy with a new `SERVER_ED25519_PRIVATE_KEY_HEX` meant copying the
pin off the server console into the page (and a stale pin was hardcoded as the default).
The page now fetches `/pubkey` on load and fills the *Server key* box with the served
`server_ed25519`.

**This is trust on first use, on purpose.** The page asks the server which key to trust and
then checks the server against that answer. It is kept as a demo talking point: the pin's
*source* is a trust boundary the rest of the protocol takes for granted.

- Whoever answers the first `/pubkey` chooses the pin. Locally that is the server, over TLS
  the browser verifies against the project CA — so the pin is exactly as strong as that TLS
  hop. Behind the cloud reverse proxy + WAF (ADR 4) it is whatever terminates public TLS:
  the intermediary the HPKE layer exists to exclude (D005) can substitute both the key and
  its signature, and §4.1.1, `server_key` and §4.3.1 all pass against its key.
- The gates themselves are unchanged. Pasting the console pin over the pre-filled value
  restores the out-of-band check, and the page shows which one is in use.

### Checklist
- [x] `client/app/page.tsx`: fetch `/pubkey` on mount, fill the box unless the user has typed;
      remove the hardcoded pin; `pinSource` (`server` / `pasted`) drives a `· TOFU` suffix on
      the Server Key chip and the Verify status note
- [x] D032 in `docs/decisions.md`; D016 marked as the conformant path it still is
- [x] `docs/protocol.md` §4.1.1 and §8: the demo exception, named as non-conformant
- [x] `docs/threat-model.md`: assumption and key-substitution section
- [x] README client run steps
- [x] `npm run build` (lint: no new findings; the 2 errors / 5 warnings on `main` are unchanged)

## Demo script (fix 1)

1. Load the page: the box is filled, Verify → green, chip reads *Verified · TOFU*.
2. Point out that the check compared the server to itself.
3. Paste the pin from the server console → chip loses *TOFU*; Verify → green for a reason.
4. Paste any other valid key → red: the gate still works when the pin is independent.

## Fix 2 — Erased epoch keys leave no bytes in the SQLite file (server)

Not a client change, but it came out of the same review. Expiry is the server erasing a
sealed epoch key (D022), and a plain `DELETE` does not erase: SQLite leaves the row in free
pages of the database file, and in WAL mode the frame that inserted it stays in `-wal` until
it is overwritten. Anyone who later gets the file plus the mnemonic could recover history
past its window.

### Checklist
- [x] `server/history_store.py`: `PRAGMA secure_delete=ON`; `wal_checkpoint(TRUNCATE)` after
      an erase that removed rows
- [x] Test: an erased key's bytes are absent from the database file and the WAL, with the key
      still in the WAL and after it was checkpointed into the main file. Each half of the fix
      alone fails one of the cases
- [x] D024 note; ADR 4 scoping item on where the keys live in AWS

Residual: the filesystem, SSD wear-levelling and volume snapshots are below SQLite. In the
cloud that is a placement question (ADR 4), not a code one.

## Out of scope

A pin list per server (ADR 4) · pin persistence in the browser (pin-on-first-use caching).

## Dependencies

None new.
