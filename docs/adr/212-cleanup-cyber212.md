# ADR 3 — Close CYBER210, open CYBER212

Branch: `212/cleanup` (on top of `212/channel_fs`) · Status: implemented on branch 212/cleanup (stacked on 212/channel_fs), awaiting push + manual review · Previous: ADR 2 channel forward secrecy · Next: ADR 4 cloud deployment

## Goal

Freeze the CYBER210 project as a record (tag `EchoSrv` + `docs/cyber210/`), remove what the
CYBER212 direction no longer needs (plaintext mode, the proxy deploy), give every echo
server its own TLS identity, and lay the documented foundation for the cloud target:
reverse proxy + WAF in front, N echo servers, one central RDS, browser picks a server.

## Decisions taken

- **Plaintext mode is removed completely** (D029): no `/ws/plain`, no Encrypt toggle, no
  E2E-OFF columns anywhere.
- **Every echo server terminates TLS itself** (D030): uvicorn on 8443 with a per-server
  cert from a project CA. In the cloud the reverse proxy re-encrypts to the server and
  verifies against that CA. Plain HTTP is removed, not optional.
- **History is per echo server** (D031): a browser that chatted with A gets nothing back
  from B. Sealed epoch keys stay on each server's host (D024 unchanged); records in the
  central database carry `server_name` and are filtered by it. Later hardening: bind the
  server identity into the storage AAD (cloud ADR).
- **CYBER210 is preserved whole**, never edited: tag `EchoSrv` and `docs/cyber210/`.

## Multi-server foundation (no behavioural change with one server)

| Item | Now | Later (cloud ADR) |
|---|---|---|
| Server identity | Ed25519 per server, pin per server | browser holds a named pin list, selects a server |
| `SERVER_NAME` | env var; TLS cert name; reported in `/api/status`; filed on records | routing key in the proxy; shown in the UI |
| Records | `server_name` column, filtered on read | unchanged |
| Epoch keys | on each server's host (SQLite volume) | unchanged — this is what makes history per-server |
| `created_at` | server clock | database clock (`now()`), one source of truth across hosts |
| Storage AAD | `owner ‖ epoch_id` | `owner ‖ epoch_id ‖ server_ed25519` |
| Sweeper | per server, idempotent | unchanged |

## Out of scope

Cloud deployment itself · server selection UI · storage-AAD change · mid-session rotation ·
any change to tag `EchoSrv`.

## Checklist

### 1. Docs
- [x] D029–D031 in `docs/decisions.md`; course-boundary note (D001–D020 = CYBER210 baseline)
- [x] `docs/protocol.md`: drop every E2E-OFF / `/ws/plain` / `text`-frame reference; §9.5–§9.6
      note `server_name`; endpoints list
- [x] `docs/threat-model.md`: drop the exhibit framing and the mitmproxy actor; single-column
      tables; add the CYBER212 direction (proxy + WAF, RDS, N servers, per-server history)
- [x] `docs/cyber212/README.md`: target architecture, the foundation table, migration notes

### 2. Layout
- [x] Move course artifacts to `docs/cyber210/` (paper, deck, diagrams, how-tos, evidence,
      GUIDEv2); add a short index there
- [x] Dockerfiles → `client/Dockerfile`, `server/Dockerfile`; `echovault-deploy/echo_db/` → `db/`
- [x] Root `docker-compose.yml` (client · server · db); delete `echovault-deploy/`
- [x] `.gitignore` paths updated

### 3. Server
- [x] Remove `/ws/plain`
- [x] `server/certs/gen-server-certs.sh` (CA + per-server leaf, SAN from `SERVER_NAME`)
- [x] uvicorn TLS on 8443 (compose command + README run line); `SERVER_NAME` in `/api/status`
- [x] `server_name` on records: schema, insert, filter (Postgres + memory), `init.sql`
- [x] Tests updated; new test: records filed under another server are not returned

### 4. Client
- [x] Remove plaintext mode (toggle, wire mode, pending gate, red rendering + CSS)
- [x] `NEXT_PUBLIC_API_URL` default `https://localhost:8443`; header comment

### 5. README
- [x] Rewrite: what EchoVault is · history (CYBER210 at `EchoSrv`, CYBER212 on main) ·
      architecture · build/run incl. trusting the server CA

### 6. Checks
- [x] pytest green · `npm run lint` / `npm run build`
- [x] `grep -ri "mitmproxy\|ws/plain" --exclude-dir=docs/cyber210 --exclude-dir=node_modules`
      returns only historical mentions in decisions.md

### 7. Delivery
- [ ] Local commits ready; user pushes and opens the PR

## Dependencies

None new.
