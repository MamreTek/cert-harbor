# CertHarbor

CertHarbor is a self-hosted control plane for domain and TLS certificate inventory, synchronization, expiry monitoring, notifications, and audit history.

The repository contains the runnable MVP: a Go API, React + Ant Design console, Docker Compose packaging, encrypted provider credentials, four read-only provider adapters, durable catalog/state snapshots and outbox delivery, expiry monitoring, notifications, audit history, and production configuration validation. The release requirements are tracked in the external requirement record at `/home/anolis/project/MamreTek/requirements/cert-harbor/REQ-001-domain-certificate-management/plan.md`.

## Run locally

Requirements: Go 1.22+, Node.js 18+, npm, and Docker Compose. Docker Compose starts PostgreSQL for catalog and durable subsystem state; local `go run` uses JSON snapshots unless `CERT_HARBOR_DATABASE_URL` is set.

Run the API:

```sh
go run ./cmd/cert-harbor
```

Run the web console in another terminal:

```sh
cd web
npm install
npm run dev
```

Or run the packaged application with Docker Compose:

```sh
cp .env.example .env
docker compose up --build
```

The application is available at <http://localhost:8080>. The API exposes `/healthz`, `/readyz`, and `/api/v1/meta`.

The Compose stack runs the API and PostgreSQL together. Stop it with `Ctrl-C`, or run `docker compose down`; persistent data is kept in the `cert_harbor_data` and `cert_harbor_postgres` volumes. To start a disposable local demo, set `CERT_HARBOR_DEMO=1` in `.env`, rebuild, and then synchronize the bundled fixture:

```sh
CERT_HARBOR_DEMO=1 docker compose up --build
curl -X POST http://localhost:8080/api/v1/provider-connections/demo-cloudflare/sync
```

For a clean demo reset, stop the stack and remove only its named volumes with `docker compose down -v`.

To run the repeatable local demo connection and synchronize the bundled sample assets:

```sh
CERT_HARBOR_DEMO=1 go run ./cmd/cert-harbor
curl -X POST http://localhost:8080/api/v1/provider-connections/demo-cloudflare/sync
curl http://localhost:8080/api/v1/domains
curl http://localhost:8080/api/v1/certificates
```

The same flow works with Compose by setting `CERT_HARBOR_DEMO=1` in `.env` before `docker compose up --build`. Fixture mode establishes the shared contract and deterministic reconciliation path. All four provider connections use live read-only adapters when encrypted credentials are supplied; fixture mode remains available for local demo and contract tests.

The scheduler runs enabled connections according to each connection's `sync_interval` (24h by default), then evaluates every known asset and drains the notification outbox. `CERT_HARBOR_SYNC_INTERVAL=15m` remains the scheduler wake-up fallback for local testing; API-created connections can set their own Go duration. Local JSON paths are used when PostgreSQL is unset; Compose stores catalog, alert, and notification state in PostgreSQL and keeps `/app/data` for fallback files and legacy migration input.

The inventory API currently provides:

- `GET /api/v1/provider-connections`
- `POST/PATCH/DELETE /api/v1/provider-connections` and connection test/sync actions
- `GET /api/v1/workspace` and `GET/POST/PATCH/DELETE /api/v1/members` for the single-installation workspace boundary
- `POST /api/v1/provider-connections/{id}/test`
- `POST /api/v1/provider-connections/{id}/sync`
- `GET /api/v1/domains` and `GET /api/v1/certificates` with `search`, `provider`, `owner`, `environment`, `status`, `expiry_state` (`healthy`, `expiring`, `expired`, `stale`, or `unknown`), `tag`, `stale`, `expires_before`, `expires_after`, `sort`, `order`, `page`, and `page_size` filters
- `GET /api/v1/export/domains.csv` and `GET /api/v1/export/certificates.csv` for complete filtered, secret-free CSV exports (not limited by the 200-row API page size)
- `GET /api/v1/sync-runs`, `GET /api/v1/sync-runs/{id}`, and `GET /api/v1/catalog/summary`
- `GET/POST/PATCH/DELETE /api/v1/alert-rules`, paginated `GET /api/v1/alerts` with `state`/`provider` filters, `GET /api/v1/alerts/{id}`, and `GET /api/v1/alert-events`
- `POST /api/v1/monitor/evaluate` plus alert `acknowledge`, `resolve`, and `suppress` actions
- `GET /api/v1/audit-events` with stable page/page-size pagination
- `GET/POST/PATCH/DELETE /api/v1/notification-channels`, channel test, alert notify, and `GET /api/v1/notification-deliveries`

Email channels use an `smtp://` or `smtps://host:port?from=...&to=...` endpoint. SMTP `username`, `password`, `from`, and `to` values are submitted as encrypted channel credentials; the API never returns them. Alert notifications are first written to a persisted outbox and retried by the background delivery loop.

Provider credentials and webhook signing secrets are encrypted with the configured application key, omitted from API responses, and excluded from audit records. When `CERT_HARBOR_DATABASE_URL` is configured, catalog, alert, and notification state restore automatically from PostgreSQL state snapshots; legacy JSON files are migrated on first startup. Connections without credentials use the bundled fixture adapter; connections with encrypted credentials use the live read-only provider clients. SMTP/SMTPS delivery and signed webhook delivery are supported through the notification outbox.

Alert rules can be scoped by asset type, provider, owner, environment, and tag. Alert evaluation is full-catalog and is not limited by the paginated inventory API. See [`docs/operations.md`](docs/operations.md) for PostgreSQL backup/recovery, sync retention, and the disposable-database integration test.

The read-only permission checklist for live adapters is in [`docs/provider-permissions.md`](docs/provider-permissions.md).

The versioned API contract is in [`docs/openapi.yaml`](docs/openapi.yaml); PostgreSQL migration and recovery guidance is in [`docs/operations.md`](docs/operations.md).

Production mode requires `CERT_HARBOR_ENCRYPTION_KEY`, `CERT_HARBOR_ADMIN_TOKEN`, `CERT_HARBOR_VIEWER_TOKEN`, and `CERT_HARBOR_DATABASE_URL`. Copy `.env.example` to `.env` for local configuration; never commit real secrets. To rotate the encryption key, set the new key in `CERT_HARBOR_ENCRYPTION_KEY`, the old key temporarily in `CERT_HARBOR_ENCRYPTION_KEY_OLD`, restart once, then remove the old-key variable.

In production, send either `Authorization: Bearer <token>` or `X-CertHarbor-Token`. Viewer tokens can read inventory, sync history, alerts, and exports; administrator tokens are required for provider tests, synchronization, monitoring evaluation, and alert state changes.

## Verify

```sh
go test ./...
make lint
make api-race
cd web && npm test && npm run build
cd .. && docker compose config
```
