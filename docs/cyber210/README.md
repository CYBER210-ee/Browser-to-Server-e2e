# CYBER210 — EchoVault, the record

This folder preserves the CYBER210 final project (Summer 2026) exactly as it was
submitted. Nothing here is maintained; the living project is on `main` and documented
in `docs/cyber212/`.

**The code as submitted is tag `EchoSrv`:**

```bash
git checkout EchoSrv          # the CYBER210 tree: client · server · mitmproxy deploy
git checkout main             # back to CYBER212
```

At that tag the README is the course operating document (roles, schedule,
deliverables) and `echovault-deploy/` holds the three-container mitmproxy stack the
live demo ran on. Run instructions for that stack are in `DEPLOY_GUIDEv2.md` here.

| File | What it is |
|---|---|
| `CYBER 210_EchoVault_Final Paper.pdf` | the final paper |
| `Cyber 210_EchoVault Live Demo Presentation_v3.pptx` | the final deck |
| `architecture_onepager_v5.svg` | architecture one-pager (browser · mitmproxy · server) |
| `echovault-securing-data-channel.{svg,png}` | data-channel diagram |
| `hpke_alice_bob_flow_v5.svg` | HPKE handshake flow |
| `DEPLOY_GUIDEv2.md` | Dockerize & deploy guide for the mitmproxy stack |
| `how_to/` | dev environment PDF, git workflow, mitmproxy CA install guide |
| `evidence/red-team/` | packet captures and mitmproxy exhibits (TLS-only vs TLS + HPKE) |

Decision entries D001–D020 in `docs/decisions.md` are the CYBER210 baseline; the
protocol and threat model at `EchoSrv` are the versions the paper describes.
