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
- Sealed epoch keys: where they live per region. Not in RDS (D024 — automated backups,
  snapshots and PITR would keep "erased" keys for the retention period and stretch the
  window). Not a container volume either (Fargate storage dies with the task; N tasks per
  region would split history). Proposed: a **regional DynamoDB table** per echo-server region
  (not a Global Table, D031) behind the existing `EpochKeyStore` interface — PITR off and no
  AWS Backup plan on it, a TTL attribute at `created_at + HISTORY_WINDOW` as a backstop only
  (TTL deletion can lag by days; the sweeper stays the authority and reads still filter on
  `created_at`), IAM access for that region's server task role only. Rejected so far: EBS
  excluded from snapshots (EC2, one instance), a small RDS per region with backups off
  (heavy), KMS crypto-shredding (7–30 day key deletion wait, per-key cost)
- Storage AAD gains `server_ed25519` (frozen-contract change, §9.4)
- Proxy upstream verification against the server CA; certificate provisioning per server
- Client hosting (static export vs `next start`) and the public TLS names

## Dependencies

To be determined during scoping.
