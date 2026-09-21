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

Production mode requires `CERT_HARBOR_ENCRYPTION_KEY`, `CERT_HARBOR_ADMIN_TOKEN`, and `CERT_HARBOR_VIEWER_TOKEN`. Copy `.env.example` to `.env` for local configuration; never commit real secrets.

## Verify

```sh
go test ./...
go vet ./...
cd web && npm test && npm run build
cd .. && docker compose config
```
