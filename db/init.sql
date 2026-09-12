-- EchoVault history records (protocol §9, D024). Runs once, on first init.
-- The server also creates this table if missing, so the two must agree.
-- Every row is an opaque blob: the browser sealed `ct` to an epoch key that
-- never reaches this database. Only owner/epoch/timestamps are readable here.
CREATE TABLE IF NOT EXISTS history_records (
  id         BIGSERIAL PRIMARY KEY,
  owner      BYTEA  NOT NULL,   -- browser Ed25519 public key (32 bytes)
  epoch_id   BYTEA  NOT NULL,   -- 16 random bytes; the sealed key lives on the server host
  enc        BYTEA  NOT NULL,   -- HPKE enc (32 bytes)
  ct         BYTEA  NOT NULL,   -- sealed record JSON ‖ tag
  created_at BIGINT NOT NULL    -- UNIX seconds, server clock
);
CREATE INDEX IF NOT EXISTS history_records_owner_idx ON history_records (owner, id);
