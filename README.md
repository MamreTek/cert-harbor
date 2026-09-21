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

The scheduler runs enabled connections once per configured interval (daily by default). Set `CERT_HARBOR_SYNC_INTERVAL=15m` or another Go duration for local testing.

The inventory API currently provides:

- `GET /api/v1/provider-connections`
- `POST /api/v1/provider-connections/{id}/test`
- `POST /api/v1/provider-connections/{id}/sync`
- `GET /api/v1/domains` and `GET /api/v1/certificates` with `search`, `provider`, `stale`, `page`, and `page_size` filters
- `GET /api/v1/export/domains.csv` and `GET /api/v1/export/certificates.csv` for filtered, secret-free CSV exports
- `GET /api/v1/sync-runs` and `GET /api/v1/catalog/summary`
- `GET /api/v1/alerts`, `GET /api/v1/alert-events`, and `GET /api/v1/alert-rules`
- `POST /api/v1/monitor/evaluate` plus alert `acknowledge`, `resolve`, and `suppress` actions

Production mode requires `CERT_HARBOR_ENCRYPTION_KEY`, `CERT_HARBOR_ADMIN_TOKEN`, and `CERT_HARBOR_VIEWER_TOKEN`. Copy `.env.example` to `.env` for local configuration; never commit real secrets.

In production, send either `Authorization: Bearer <token>` or `X-CertHarbor-Token`. Viewer tokens can read inventory, sync history, alerts, and exports; administrator tokens are required for provider tests, synchronization, monitoring evaluation, and alert state changes.

## Verify

```sh
go test ./...
go vet ./...
cd web && npm test && npm run build
cd .. && docker compose config
```
