# CertHarbor

CertHarbor is a self-hosted control plane for domain and TLS certificate inventory, synchronization, expiry monitoring, notifications, and audit history.

This branch initializes the runnable foundation: a Go API with health/readiness endpoints, a React + Ant Design console shell, Docker Compose packaging, and production configuration validation. The full provider synchronization and alerting scope is tracked in the external requirement record at `/home/anolis/project/MamreTek/requirements/cert-harbor/REQ-001-domain-certificate-management/plan.md`.

## Run locally

Requirements: Go 1.22+, Node.js 18+, npm, and Docker Compose.

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

Or run the packaged application:

```sh
docker compose up --build
```

The application is available at <http://localhost:8080>. The API exposes `/healthz`, `/readyz`, and `/api/v1/meta`.

To run the repeatable local demo connection and synchronize the bundled sample assets:

```sh
CERT_HARBOR_DEMO=1 go run ./cmd/cert-harbor
curl -X POST http://localhost:8080/api/v1/provider-connections/demo-cloudflare/sync
curl http://localhost:8080/api/v1/domains
curl http://localhost:8080/api/v1/certificates
```

The same flow works with Compose by setting `CERT_HARBOR_DEMO=1` in `.env` before `docker compose up --build`. The current fixture adapters establish the shared contract and deterministic reconciliation path; live provider SDK/API calls and delivery integrations remain subsequent implementation slices.

The scheduler runs enabled connections once per configured interval (daily by default). Set `CERT_HARBOR_SYNC_INTERVAL=15m` or another Go duration for local testing. The catalog, alert state, and notification state use `CERT_HARBOR_DATA_PATH`, `CERT_HARBOR_ALERTS_PATH`, and `CERT_HARBOR_NOTIFICATIONS_PATH`; Compose defaults all three to the persistent `/app/data` volume.

The inventory API currently provides:

- `GET /api/v1/provider-connections`
- `POST/PATCH/DELETE /api/v1/provider-connections` and connection test/sync actions
- `GET /api/v1/workspace` and `GET/POST/PATCH/DELETE /api/v1/members` for the single-installation workspace boundary
- `POST /api/v1/provider-connections/{id}/test`
- `POST /api/v1/provider-connections/{id}/sync`
- `GET /api/v1/domains` and `GET /api/v1/certificates` with `search`, `provider`, `stale`, `page`, and `page_size` filters
- `GET /api/v1/export/domains.csv` and `GET /api/v1/export/certificates.csv` for filtered, secret-free CSV exports
- `GET /api/v1/sync-runs` and `GET /api/v1/catalog/summary`
- `GET/POST/PATCH/DELETE /api/v1/alert-rules`, `GET /api/v1/alerts`, and `GET /api/v1/alert-events`
- `POST /api/v1/monitor/evaluate` plus alert `acknowledge`, `resolve`, and `suppress` actions
- `GET /api/v1/audit-events` with stable page/page-size pagination
- `GET/POST/PATCH/DELETE /api/v1/notification-channels`, channel test, alert notify, and `GET /api/v1/notification-deliveries`

Provider credentials and webhook signing secrets are encrypted with the configured application key, omitted from API responses, and excluded from audit records. The catalog snapshot is written atomically to `CERT_HARBOR_DATA_PATH` (the Compose deployment persists it in the `cert_harbor_data` volume). The current adapters use the bundled fixture contract; live provider API clients and SMTP delivery remain follow-up implementation work.

The read-only permission checklist for the planned live adapters is in [`docs/provider-permissions.md`](docs/provider-permissions.md).

Production mode requires `CERT_HARBOR_ENCRYPTION_KEY`, `CERT_HARBOR_ADMIN_TOKEN`, and `CERT_HARBOR_VIEWER_TOKEN`. Copy `.env.example` to `.env` for local configuration; never commit real secrets.

In production, send either `Authorization: Bearer <token>` or `X-CertHarbor-Token`. Viewer tokens can read inventory, sync history, alerts, and exports; administrator tokens are required for provider tests, synchronization, monitoring evaluation, and alert state changes.

## Verify

```sh
go test ./...
go vet ./...
cd web && npm test && npm run build
cd .. && docker compose config
```
