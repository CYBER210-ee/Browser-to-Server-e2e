# Installing the mitmproxy CA Certificate

This guide explains how to trust our local **mitmproxy** CA so that `https://localhost`
(served through the mitmproxy reverse proxy) loads without certificate warnings.

> **Why this is needed:** mitmproxy terminates TLS on port `443` using a leaf
> certificate it signs on the fly with its own Certificate Authority (CA). Your
> browser doesn't trust that CA by default, so you must install it once.

---

## 0. Get the certificate file

The proxy operator (whoever runs `docker compose up`) should send you the **public**
CA certificate. It is generated on first start in the `mitmproxy/certs/` directory:

| File | Use it for |
|------|------------|
| `mitmproxy-ca-cert.pem` | Linux, Firefox, macOS, `certutil` |
| `mitmproxy-ca-cert.cer` | Windows (double-click install) |
| `mitmproxy-ca-cert.p12` | Windows / Android (cert-only, no password) |

> ⚠️ **NEVER share or install `mitmproxy-ca.pem`.** That file contains the CA
> **private key**. Anyone holding it can silently decrypt HTTPS traffic from any
> machine that trusts this CA. Distribute only the `*-cert.*` files above.

> 🔒 **Security note:** Installing this CA means any traffic you send to a host
> the proxy controls can be decrypted by the proxy operator. Only install it on a
> machine/profile used for this testing, and **remove it when you're done**
> (see the last section).

---

## Windows 11

### Chrome & Edge (use the Windows certificate store)

Chrome and Edge both trust the Windows system store, so one install covers both.

**Option A — Double-click (Current User):**
1. Double-click `mitmproxy-ca-cert.cer`.
2. Click **Install Certificate…**
3. Store Location: **Current User** → **Next**.
4. Choose **Place all certificates in the following store** → **Browse…**
5. Select **Trusted Root Certification Authorities** → **OK** → **Next** → **Finish**.
6. Accept the security warning → **Yes**.
7. **Fully restart** Chrome/Edge (close all windows).

**Option B — PowerShell (machine-wide, needs Administrator):**
```powershell
Import-Certificate -FilePath "C:\path\to\mitmproxy-ca-cert.cer" `
  -CertStoreLocation Cert:\LocalMachine\Root
```
Then restart the browser.

> To manage/verify later, run `certmgr.msc` (current user) or `certlm.msc`
> (local machine) → **Trusted Root Certification Authorities → Certificates**,
> and look for an entry issued to **mitmproxy**.

### Firefox (uses its own certificate store)

Firefox ignores the Windows store by default.

1. **☰ menu → Settings → Privacy & Security**.
2. Scroll to **Certificates → View Certificates…**
3. **Authorities** tab → **Import…**
4. Select `mitmproxy-ca-cert.pem`.
5. Tick **Trust this CA to identify websites** → **OK**.
6. Reload the page (no restart needed).

> *Alternative:* set `security.enterprise_roots.enabled = true` in `about:config`
> to make Firefox also trust certs from the Windows store (useful if you already
> did the Chrome/Edge step).

---

## Linux

On Linux, **Chrome/Chromium/Edge use the NSS database** (`~/.pki/nssdb`), Firefox
uses its **own profile store**, and command-line tools (`curl`, `wget`) use the
**system store**. They are independent — install into whichever you need.

### Chrome / Chromium / Edge (NSS database)

Install the `certutil` tool first:
```bash
# Debian / Ubuntu
sudo apt install libnss3-tools
# Fedora / RHEL
sudo dnf install nss-tools
# Arch
sudo pacman -S nss
```

Add the CA to your user NSS DB:
```bash
certutil -d sql:$HOME/.pki/nssdb -A \
  -t "C,," -n "mitmproxy" -i mitmproxy-ca-cert.pem
```
> If `~/.pki/nssdb` doesn't exist yet, create it first:
> `mkdir -p $HOME/.pki/nssdb && certutil -d sql:$HOME/.pki/nssdb -N --empty-password`

Then fully restart the browser. Verify with:
```bash
certutil -d sql:$HOME/.pki/nssdb -L | grep -i mitmproxy
```

### Firefox (per-profile store)

**GUI (easiest):** ☰ → **Settings → Privacy & Security → Certificates →
View Certificates… → Authorities → Import…** → choose `mitmproxy-ca-cert.pem` →
tick **Trust this CA to identify websites** → **OK**.

**CLI (scriptable):**
```bash
for profile in $HOME/.mozilla/firefox/*.default*; do
  certutil -d sql:"$profile" -A -t "C,," -n "mitmproxy" -i mitmproxy-ca-cert.pem
done
```

### System-wide (curl, wget, and as a base for some setups)

**Debian / Ubuntu** — the file **must** end in `.crt`:
```bash
sudo cp mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt
sudo update-ca-certificates
```

**Fedora / RHEL / CentOS:**
```bash
sudo cp mitmproxy-ca-cert.pem /etc/pki/ca-trust/source/anchors/mitmproxy.pem
sudo update-ca-trust
```

**Arch:**
```bash
sudo trust anchor --store mitmproxy-ca-cert.pem
```

> ⚠️ Installing system-wide does **not** automatically make Chrome or Firefox
> trust the CA — those use NSS/their own store (steps above). System-wide mainly
> helps CLI tools and apps that read the OS bundle.

---

## Verify it worked

1. Browse to **`https://localhost`**.
2. The padlock should show a valid/secure connection (no warning).
3. Click the padlock → view the certificate → the **issuer** should be **mitmproxy**.

If you still see `NET::ERR_CERT_AUTHORITY_INVALID` / "Warning: Potential Security
Risk": you installed into the wrong store for that browser, or you didn't fully
restart it. Re-check the matching section above.

---

## Removing the certificate (when you're done)

**Windows (Chrome/Edge):** `certmgr.msc` → Trusted Root Certification Authorities →
Certificates → right-click **mitmproxy** → **Delete**.
PowerShell: `Get-ChildItem Cert:\CurrentUser\Root | ? Subject -match mitmproxy | Remove-Item`

**Windows (Firefox):** Settings → Certificates → View Certificates → Authorities →
select **mitmproxy** → **Delete or Distrust…**

**Linux (NSS / Chrome):**
```bash
certutil -d sql:$HOME/.pki/nssdb -D -n "mitmproxy"
```

**Linux (Firefox):** same as NSS but point `-d` at the profile dir, or remove via
the GUI Authorities tab.

**Linux (system-wide):** delete the file you copied, then re-run
`sudo update-ca-certificates` (Debian/Ubuntu) or `sudo update-ca-trust` (Fedora).

---

## Quick reference

| Platform | Browser | Where it's installed |
|----------|---------|----------------------|
| Windows 11 | Chrome / Edge | Windows store → *Trusted Root Certification Authorities* |
| Windows 11 | Firefox | Firefox → Settings → Certificates → Authorities |
| Linux | Chrome / Chromium / Edge | NSS DB via `certutil` (`~/.pki/nssdb`) |
| Linux | Firefox | Firefox Authorities tab, or `certutil` on the profile |
| Linux | curl / wget / system | `update-ca-certificates` / `update-ca-trust` |
