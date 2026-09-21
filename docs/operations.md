# CertHarbor operations

## Persistence modes

Local `go run ./cmd/cert-harbor` uses atomic JSON snapshots by default. Docker Compose starts PostgreSQL 16 and sets `CERT_HARBOR_DATABASE_URL`, so the catalog, alert rules/events, and notification channels/deliveries/outbox are restored from PostgreSQL state snapshots and mutations are written there. A legacy alert or notification JSON file is migrated into PostgreSQL the first time the database-backed deployment starts; the protected `/app/data` volume remains available for local fallback and migration input.

For production, set `POSTGRES_PASSWORD` and `CERT_HARBOR_DATABASE_URL` through a secret manager or deployment secret. The Compose default derives the database URL from `POSTGRES_USER`, `POSTGRES_PASSWORD`, and `POSTGRES_DB`; set `CERT_HARBOR_DATABASE_URL` explicitly when the password contains URL-reserved characters. Do not commit those values to `.env` or expose PostgreSQL publicly.

## Sync reconciliation and retention

Each successful provider sync reconciles assets for that connection. Assets absent from a successful response are retained with `stale=true` and remain queryable so operators can investigate provider-side removal or permission changes. A failed, cancelled, or partially unreadable sync does not change the last-known inventory. CertHarbor does not automatically purge stale assets in the MVP; deleting the provider connection explicitly removes its associated assets.

## Encryption-key rotation

Set the replacement value in `CERT_HARBOR_ENCRYPTION_KEY` and the previous value in `CERT_HARBOR_ENCRYPTION_KEY_OLD`. On startup CertHarbor re-encrypts provider credentials and notification secrets without changing their ownership or IDs. Confirm the service is healthy and test one provider connection and notification channel, then remove `CERT_HARBOR_ENCRYPTION_KEY_OLD` and restart again.

## Backup and recovery

Back up the PostgreSQL catalog/state snapshots and the `/app/data` volume together. The volume is required when a deployment still has legacy JSON fallback or migration files. The encryption key is required to decrypt provider and notification credentials after restore.

```sh
docker compose exec -T postgres pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" > cert-harbor-catalog.sql
docker run --rm -v cert_harbor_data:/data -v "$PWD":/backup alpine \
  tar czf /backup/cert-harbor-data.tgz -C /data .
```

To recover, restore the SQL dump, restore the data volume, and start CertHarbor with the same encryption key. Verify `/readyz`, inventory counts, alert history, and notification delivery history before routing production alerts.

## PostgreSQL integration test

When a disposable PostgreSQL instance is available, run the catalog round-trip test:

```sh
CERT_HARBOR_TEST_DATABASE_URL='postgres://cert_harbor:password@127.0.0.1:5432/cert_harbor?sslmode=disable' \
  go test ./internal/catalog -run TestPostgresCatalogRoundTrip -count=1
```

The normalized in-process inventory baseline can be repeated with 100,000 domains and 100,000 certificates:

```sh
go test ./internal/catalog -run '^$' -bench BenchmarkListNormalizedAssets100k -benchtime=1x -count=1
```

The benchmark exercises filtered, sorted, paginated reads; the nominal target is under 500 ms per query. PostgreSQL latency should be checked separately with the disposable database test and deployment-sized data.
