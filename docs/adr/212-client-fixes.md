# ADR 5 — Client fixes

Branch: `agent/cs212/client_fixes` (on top of `main`) · Status: fix 1 implemented, awaiting push + manual review · Previous: ADR 4 cloud deployment (scoping)

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

## Out of scope

A pin list per server (ADR 4) · pin persistence in the browser (pin-on-first-use caching) ·
any server change.

## Dependencies

None new.
