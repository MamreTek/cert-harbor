CREATE TABLE IF NOT EXISTS cert_harbor_catalog_snapshots (
  snapshot_id SMALLINT PRIMARY KEY,
  payload JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);
