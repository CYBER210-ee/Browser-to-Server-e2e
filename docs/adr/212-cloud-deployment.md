# ADR 4 — Cloud deployment: global echo servers, one RDS

Branch: `212/cloud` (on top of `212/cleanup`) · Status: scoping · Previous: ADR 3 cleanup

## Goal

Deploy EchoVault to the cloud as drawn in `docs/cyber212/Cloud_Deployment.pptx`: echo
servers in several regions behind a reverse proxy + WAF, one central Amazon RDS for sealed
history, and the browser choosing which echo server it talks to — so a prompt reaches the
frontier-model clouds from the echo server's region, not the user's (location obfuscation).

## Done so far

- [x] Deck read; the slide rebuilt as `docs/cyber212/cloud-deployment.svg` and placed in the
      top-level README and `docs/cyber212/README.md` with an intro paragraph

## To scope (questions first, per the ADR cycle)

- Cloud target and IaC (which provider, ECS/EKS/VMs, how the proxy + WAF are provisioned)
- Server selection in the browser: named pin list `{name, url, pin}`; how pins are provisioned
- Region set for the first deployment; `SERVER_NAME` per region
- RDS: TLS trust chain (RDS CA vs the project db CA), credentials, `created_at` from `now()`
- Storage AAD gains `server_ed25519` (frozen-contract change, §9.4)
- Proxy upstream verification against the server CA; certificate provisioning per server
- Client hosting (static export vs `next start`) and the public TLS names

## Dependencies

To be determined during scoping.
