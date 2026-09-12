# EchoVault — Dockerize & Deploy (client · server · mitmproxy TLS terminator)

A start-to-finish, copy-paste guide to take the EchoVault echo demo from a vanilla
machine to a 3-container deployment on the ZeroTier test box **10.188.199.221**.
**Works whether your local machine is Linux or Windows 11** — see the
*Local environment* section, then follow each step's 🐧 Linux / 🪟 Windows notes.

| Container | Image | Role | Listens (internal) |
|---|---|---|---|
| `mitmproxy` | `mitmproxy/mitmproxy` | **TLS termination + reverse proxy** for both hostnames | 8080 (→ host **443**), 8081 (web UI) |
| `echo_client` | `echo_client:1.0` | Next.js chat UI (`next start`) | 3000 |
| `echo_server` | `echo_server:1.0` | FastAPI echo / WebSocket backend | 8000 |

All three sit on one shared Docker network (`proxynet`). **mitmproxy is the only
public ingress.** It terminates TLS using a self-generated cert that covers
`echo.client.test` and `echo.server.test`, then forwards the **decrypted** traffic
to the right backend over plain http/ws — which is what makes the TLS-vs-E2E
exhibit work.

```
                         host :443 (TLS, our cert)            proxynet (plain http/ws)
  Browser  ──────────────────────────────────────►  ┌─────────────┐  ──► client:3000  (Next.js UI)
  https://echo.client.test                           │  mitmproxy  │
  wss://echo.server.test/ws  ────────────────────►   │ TLS-term +  │  ──► server:8000  (FastAPI /ws)
                                                      │ host-router │
  http://mitmproxy.test:8081  (watch decrypted) ◄──  └─────────────┘
              SNI decides the backend (route.py)
```

---

## Local environment — Linux or Windows 11 (read first)

Everything is built with Docker and driven by **bash** scripts (`gen-certs.sh`,
`scripts/01..03`). Docker images are OS-independent; only the *shell* and the
*cert/hosts steps* differ between Linux and Windows.

### 🐧 Linux
Native. You need: `docker` + `docker compose` v2, `openssl`, `ssh`/`scp`, and
`bash`. Nothing special — run the scripts directly.

### 🪟 Windows 11
Pick **one** bash environment to run the scripts in. **WSL2 is strongly
recommended** (it's a real Linux, so the bash scripts and `openssl` work
unmodified):

1. **Install Docker Desktop** and enable the **WSL2 backend**
   (Settings → General → *Use the WSL 2 based engine*), plus
   Settings → Resources → WSL Integration → enable your Ubuntu distro.
2. **Install WSL2 + Ubuntu:** in an admin PowerShell, `wsl --install -d Ubuntu`,
   then open the **Ubuntu** terminal for all script steps.
3. **Keep the project inside the WSL2 filesystem** (e.g. `~/echovault-deploy`),
   **not** under `/mnt/c/...` — this avoids slow I/O and CRLF line-ending issues.
4. `openssl`, `ssh`, `scp`, `bash` are already in Ubuntu. Docker commands work
   because of the WSL integration above.

> **Line endings (Windows gotcha):** if you cloned the repo on Windows, Git may
> have converted scripts to CRLF, which makes bash fail with
> `bad interpreter: /usr/bin/env bash^M`. Fix once inside WSL2/Ubuntu:
> ```bash
> sudo apt-get install -y dos2unix
> dos2unix mitmproxy/gen-certs.sh scripts/*.sh
> # or: git config --global core.autocrlf input   (before cloning)
> ```

> **Git Bash alternative:** Git Bash + Docker Desktop also works for most steps,
> but `gen-certs.sh` uses bash process substitution and is happiest in WSL2. If
> you use Git Bash and `gen-certs.sh` errors, switch that step to WSL2.

The two places Windows genuinely differs from Linux are **(a) the hosts file
location** and **(b) trusting the CA** — both called out in Steps 2 and 6.

---

## What you'll do (~10 minutes)

1. Stage the three folders locally.
2. Generate the TLS cert + CA **(once; publish `ca.crt`)**.
3. Build the two images locally; pull mitmproxy.
4. Save images to a tarball and ship to the box.
5. Load + `docker compose up` on the box.
6. Trust the CA + add hosts entries on whatever machine runs the browser.
7. Open `https://echo.client.test` and watch traffic in mitmweb.

Bundle layout (mirrors the final `/opt`):

```
opt/
├── echo_server/   Dockerfile, docker-compose.yml, main.py, requirements.txt
├── echo_client/   Dockerfile, .dockerignore, docker-compose.yml   (+ you add the Next.js source)
└── mitmproxy/     docker-compose.yml, route.py, gen-certs.sh
scripts/
├── 01-build-local.sh
├── 02-save-and-ship.sh
└── 03-deploy-on-box.sh
```

---

## Prerequisites

- **Local (Linux or Windows 11/WSL2):** Docker + Docker Compose v2
  (`docker compose version`), `openssl`, `ssh`/`scp`, `bash`.
- **ZeroTier test box (10.188.199.221):** Docker + Compose v2, SSH access, a user
  in the `docker` group (or sudo), and joined to your ZeroTier network.
- The EchoVault repo checked out locally (you need the `client/` source to build
  its image). On Windows, clone it **inside** WSL2.

---

## Step 1 — Stage the three folders locally

🐧🪟 Same commands (run them in your bash shell — Linux terminal or WSL2 Ubuntu):

```bash
mkdir -p ~/echovault-deploy
cp -r /path/to/bundle/opt/*   ~/echovault-deploy/      # echo_server, echo_client, mitmproxy
cp -r /path/to/bundle/scripts ~/echovault-deploy/

# Add the Next.js source into the client build context:
cp -r /path/to/repo/client/.   ~/echovault-deploy/echo_client/
# Add main.py + requirements.txt to echo_server
cp -r /path/to/repo/server/main.py ~/echovault-deploy/echo_server/
cp -r /path/to/repo/server/requirements.txt ~/echovault-deploy/echo_server/
```

---

## Step 2 — Generate the TLS cert + CA **ONCE**, commit it, reuse it forever (should be done skip step)

One person runs this **a single time**, commits the whole `certs/` directory, and
the entire team reuses it. After that, `gen-certs.sh` is a **no-op** (it detects
existing certs and reuses them), and `02-save-and-ship.sh` ships the committed
certs without regenerating — so you can change code and rebuild every week
**without ever re-cutting certs or re-installing trust**.

🐧🪟 Run in bash (Linux or WSL2 Ubuntu):

```bash
cd ~/echovault-deploy/mitmproxy
./gen-certs.sh                 # first run: generates; later runs: reuse (no-op)
git add certs && git commit -m "EchoVault test certs (CA + leaf) — shared, reused"
```

This creates `./certs/`:

| File | What it is | Where it goes |
|---|---|---|
| `ca.crt` | the test **CA** | install in each browser (Step 6); also commit so teammates can |
| `ca.key` | the CA **private key** | committed too (see note) — used only to reissue the leaf |
| `echovault.pem` | key + leaf + CA chain | used by mitmproxy (`--certs`) |
| `echovault.crt` | the leaf cert | reference only |

**The cert is name-only and location-independent.** It carries only
`DNS:echo.client.test, DNS:echo.server.test` — no IP — so the *same* cert is valid
wherever those names resolve (localhost, the ZeroTier IP, a future IP). You do
**not** rebuild certs when the box IP changes; you only would if the *hostnames*
change.

> **Commit the whole `certs/` directory (keys included) for this project.** These
> are throwaway test keys for a self-contained, enclosed echo system — there is
> nothing sensitive to protect, and committing them means the team never has to
> regenerate or re-trust. The one thing to understand: anyone who has `ca.key`
> **and** whom a victim has been convinced to install this CA could MITM that
> victim — so keep this CA installed **only** on the test machines and remove it
> when the demo is done (Teardown). It is not a general-purpose root.
>
> **Regenerating is opt-in and rarely needed** (`gen-certs.sh` reuses by default):
> - `FORCE=1 ./gen-certs.sh` — reissue the **leaf** only; the **CA stays the
>   same**, so installed trust keeps working (no reinstall). Commit the new leaf.
> - `FORCE_CA=1 ./gen-certs.sh` — mint a **brand-new CA**; everyone must reinstall
>   `ca.crt`. Only do this if the CA key is ever exposed beyond the team.

---

## Step 3 — Build images locally

🐧🪟 Same (Linux terminal or WSL2 Ubuntu, with Docker Desktop running on Windows):

```bash
cd ~/echovault-deploy
./scripts/01-build-local.sh
```

---

## Step 4 — Ship to the test box

```bash
cd ~/echovault-deploy
BOX=10.188.199.221 SSH_USER=youruser ./scripts/02-save-and-ship.sh
```

`docker save`s all three images to `echovault-images.tar` and ships it + the
compose files + the **committed** `certs/` + `route.py` to `/tmp/echovault/` on
the box. It **reuses** the existing certs (no regeneration); it only bootstraps
them if `certs/` is missing entirely (first-ever run). So re-shipping after a code
change never disturbs the team's installed trust.
🪟 On Windows do this from WSL2 (it uses `scp`/`ssh`).

**No SSH key set up? That's fine — you'll type your password just once.** The
script opens a single shared SSH connection (multiplexing) and reuses it for all
five transfers, so you're not prompted repeatedly. Options:
- **Password (default):** just run it; enter the box password at the one prompt.
- **Passwordless:** `ssh-copy-id $SSH_USER@10.188.199.221` once, then no prompt.
- **Fully unattended:** install `sshpass` and run
  `SSHPASS='thepassword' BOX=10.188.199.221 SSH_USER=youruser ./scripts/02-save-and-ship.sh`.
  
---

## Step 5 — Deploy on the box

```bash
ssh youruser@10.188.199.221
bash /tmp/echovault/03-deploy-on-box.sh
```

Expected:
```
NAMES         STATUS    PORTS
mitmproxy     Up ...    0.0.0.0:443->8080/tcp, 0.0.0.0:8081->8081/tcp
echo_client   Up ...
echo_server   Up ...
```

No images are built on the box — they're loaded from the tarball.

---

## Step 6 — Trust the CA + resolve the hostnames (browser machine)

Do this on whatever machine runs the browser. It must be on the ZeroTier network.

### a) Resolve the names to the box

**🐧 Linux** — edit `/etc/hosts` (`sudo`):
```
10.188.199.221   echo.client.test echo.server.test mitmproxy.test
```

**🪟 Windows 11** — edit `C:\Windows\System32\drivers\etc\hosts` **as
Administrator** (right-click Notepad → *Run as administrator* → open that file),
add the same line:
```
10.188.199.221   echo.client.test echo.server.test mitmproxy.test
```
> This is the **Windows** hosts file (the browser runs on Windows). WSL2 has its
> own `/etc/hosts`, but that does **not** affect your Windows browser.
> Verify from PowerShell: `ping echo.client.test` should hit `10.188.199.221`.

### b) Trust `ca.crt`

Copy `mitmproxy/certs/ca.crt` to the browser machine, then:

**🐧 Linux**
- **Chrome / Chromium / Edge (NSS):**
  ```bash
  certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "EchoVault Test CA" -i ca.crt
  ```
  (install `libnss3-tools` first if needed). Fully restart the browser.
- **Firefox:** Settings → Privacy & Security → Certificates → View Certificates →
  Authorities → Import → pick `ca.crt` → tick *Trust this CA to identify websites*.

**🪟 Windows 11**
- **Chrome / Edge (Windows system store):** double-click `ca.crt` →
  **Install Certificate** → **Current User** → *Place all certificates in the
  following store* → **Trusted Root Certification Authorities** → Finish → accept
  the warning. **Fully restart** the browser.
  PowerShell alternative:
  ```powershell
  Import-Certificate -FilePath .\ca.crt -CertStoreLocation Cert:\CurrentUser\Root
  ```
- **Firefox (its own store, any OS):** Settings → Privacy & Security →
  Certificates → View Certificates → Authorities → Import → `ca.crt` →
  *Trust this CA to identify websites*.

> ⚠️ Distribute only `ca.crt`. Never share `ca.key`. Remove the CA from trust when
> the demo is done (see Teardown).
>
> **If you regenerated the cert with `FORCE_CA=1`**, the CA changed — remove the
> old "EchoVault Test CA" entry first, then re-import. `gen-certs.sh` prints the
> CA SHA-256 fingerprint so you can confirm the browser matches what mitmproxy serves.

---

## Step 7 — Verify & run the demo

1. **Open** `https://echo.client.test` — padlock valid (issuer "EchoVault Test
   CA"), header flips to **Online**, messages echo back `… (Echo)`.
2. **Watch the wire** at `http://mitmproxy.test:8081` (mitmweb, password
   `Pa44word1234`): the page load to `echo.client.test`, and the WebSocket to
   `echo.server.test/ws` with each frame's **decrypted** JSON.
3. **The exhibit:** E2E **OFF** → `text` is the prompt in cleartext in mitmweb
   (TLS alone didn't hide it from the terminating middlebox). E2E **ON** (HPKE) →
   the same frame is only `{ enc, ct }` ciphertext. Same proxy, same TLS,
   different visibility.

CLI sanity checks (🐧 Linux / 🪟 WSL2 or PowerShell; with the CA trusted):
```bash
curl --cacert mitmproxy/certs/ca.crt https://echo.server.test/api/health   # {"status":"ok"}
curl http://10.188.199.221:8000/api/health   # should refuse/timeout (proxy is the only ingress)
```
🪟 PowerShell equivalent of the first check:
`curl.exe --cacert .\certs\ca.crt https://echo.server.test/api/health`

---

## Troubleshooting (incl. Windows-specific)

| Symptom | Cause / Fix |
|---|---|
| `bad interpreter: .../bash^M` or `$'\r': command not found` | 🪟 CRLF line endings. Run `dos2unix gen-certs.sh scripts/*.sh` in WSL2. |
| `docker: command not found` in WSL2 | Enable Docker Desktop → Settings → Resources → **WSL Integration** for your distro; reopen the terminal. |
| `NET::ERR_CERT_AUTHORITY_INVALID` | CA not trusted in *this* browser's store (Chrome/Edge=OS store on Windows / NSS on Linux; Firefox=own store). Re-do Step 6b and fully restart the browser. |
| `tls alert certificate unknown` (mitmproxy log) | Browser trusts a **stale** CA (regenerated since install). Remove old "EchoVault Test CA", re-import current `ca.crt`; match the printed fingerprint. |
| Page loads but stays **Connecting…** | WS URL not baked. Rebuild `echo_client` with `NEXT_PUBLIC_API_URL=https://echo.server.test`; check `docker logs echo_server`. |
| `404 unknown host` from proxy | Hostname not in `route.py` (only the two `.test` names route). Check the hosts file + SNI. |
| `ping echo.client.test` fails on Windows | You edited WSL2's `/etc/hosts`, not the **Windows** hosts file. Edit `C:\Windows\System32\drivers\etc\hosts` as Administrator. |
| `network proxynet not found` | `docker network create proxynet` (the deploy script does this — network before `up`). |
| WebSocket 1006 / closes instantly | Backend unreachable on `proxynet`. Confirm the compose service name is `server` and it's `Up`. |
| Proxy can't bind / restarts | We publish `443:8080` (no privileged-port bind needed). Check `docker logs mitmproxy` for cert path errors (`/certs/echovault.pem` mounted?). |

---

## Teardown

```bash
# On the box:
docker compose -f /opt/mitmproxy/docker-compose.yml   down
docker compose -f /opt/echo_client/docker-compose.yml down
docker compose -f /opt/echo_server/docker-compose.yml down
docker network rm proxynet
```
Remove the test CA from trust when finished:
- **🐧 Linux NSS:** `certutil -d sql:$HOME/.pki/nssdb -D -n "EchoVault Test CA"`
- **🪟 Windows:** `certmgr.msc` → Trusted Root Certification Authorities → delete **EchoVault Test CA** (or `Get-ChildItem Cert:\CurrentUser\Root | ? Subject -match EchoVault | Remove-Item`)
- **Firefox (any OS):** Settings → Certificates → Authorities → select it → Delete or Distrust.

---

## File reference

- `opt/mitmproxy/route.py` — SNI→backend router addon (dual-vhost proxy).
- `opt/mitmproxy/gen-certs.sh` — CA (stable) + name-only leaf + `echovault.pem`; prints CA fingerprint.
- `opt/mitmproxy/docker-compose.yml` — mitmweb, reverse mode, per-domain `--certs`, `443:8080` + `8081`.
- `opt/echo_server/Dockerfile` — slim Python image, uvicorn on 8000.
- `opt/echo_client/Dockerfile` — multi-stage Next.js build → `next start` on 3000.
- `scripts/01..03` — build locally → save & ship → load & deploy on the box.
