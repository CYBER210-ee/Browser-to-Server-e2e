# EchoVault — CYBER212

The CYBER210 project (tag `EchoSrv`, record under `docs/cyber210/`) proved one claim on a
laptop: browser-to-server HPKE keeps prompt content away from a TLS-terminating proxy.
CYBER212 takes the same system to the cloud and extends the claim to storage and to the
wire after the fact.

## What changed so far (`main`, ADRs 1–3)

| ADR | Checklist | Result |
|---|---|---|
| 1 — epoch expiry | `docs/adr/212-epoch-expiry.md` | History sealed in the browser to random epoch keys; keys sealed to the mnemonic identity; server erases keys after a window; Postgres holds only opaque blobs (D021–D025) |
| 2 — channel forward secrecy | `docs/adr/212-channel-forward-secrecy.md` | Both HPKE directions seal to per-connection ephemeral keys; server speaks first with a signed `server_key`; `/pubkey` is the Ed25519 pin only (D026–D028) |
| 3 — cleanup | `docs/adr/212-cleanup-cyber212.md` | Plaintext mode and the proxy stack removed; per-server TLS; history per server; this document (D029–D031) |

Living documents: `docs/protocol.md` (wire contract), `docs/threat-model.md`,
`docs/decisions.md`.

## Target architecture

```
                 public TLS                      per-server TLS (server CA, D030)
  Browser ───────────────────▶ Reverse proxy + WAF ──┬──▶ echo server A  (Ed25519 A · cert A · epoch keys A)
   picks a server, holds a                          ├──▶ echo server B  (Ed25519 B · cert B · epoch keys B)
   pin per server                                   └──▶ echo server N
                                                                 │  TLS verify-full (db CA)
                                                                 ▼
                                                     one central Postgres (RDS)
                                                     sealed records only, filed by server_name
```

- The proxy and WAF are the modeled TLS-terminating intermediary. They see handshake public
  keys and `{seq, ct}` frames. They re-encrypt to the echo server and verify its certificate
  against the project server CA.
- Each echo server is its own trust domain: own Ed25519 identity (the browser's pin), own
  TLS certificate, own SQLite of sealed epoch keys on its own host.
- The database is shared and cannot decrypt anything. History is per server (D031): a
  browser that talked to A gets nothing from B, because B never holds A's epoch keys and
  filters records by `server_name`.

## Foundation already in place (inert with one server)

| Item | Now | Cloud ADR |
|---|---|---|
| Server identity | Ed25519 per server; one pin in the page | named pin list; server picker in the UI |
| `SERVER_NAME` | env var; TLS cert name; in `/api/status`; filed on every record | routing key at the proxy; shown in the UI |
| Records | `server_name` column, filtered on read | unchanged |
| Epoch keys | SQLite volume on each server host | unchanged — this is what makes history per server |
| `created_at` | server clock | database clock (`now()`), one source of truth across hosts |
| Storage AAD | `owner ‖ epoch_id` | `owner ‖ epoch_id ‖ server_ed25519` — a record from A can never open in a session with B |
| Sweeper | per server, idempotent | unchanged |
| TLS | uvicorn on 8443 with a cert from `server/certs/gen-server-certs.sh` | proxy upstream verification against the same CA; cert provisioning per server |

## Migration notes for the cloud ADR

1. **Server selection in the browser.** Replace the single pin box with a list of
   `{name, url, pin}`; everything else in the page is already parameterised by `httpBase`.
2. **Storage AAD change** is a frozen-contract change (§9.4): both sides move together, and
   records sealed under the old AAD stop opening — do it while the history window is short,
   or accept the reset.
3. **Timestamps.** Move `created_at` to `now()` in SQL so expiry does not depend on N server
   clocks agreeing.
4. **Certificates.** The server CA in `server/certs/` becomes the trust anchor the proxy
   configures for upstream verification; issue one leaf per `SERVER_NAME`.
5. **Sweeper.** Each server erases only its own epoch keys; record deletion in the shared
   database is by `(server_name, owner, epoch_id)` and idempotent, so N sweepers do not
   interfere.
