.PHONY: api-test api-vet api-race lint web-test web-build compose-config docker-up docker-down test

api-test:
	go test ./...

api-vet:
	go vet ./...

api-race:
	go test -race ./...

lint: api-vet

web-test:
	cd web && npm test

web-build:
	cd web && npm run build

compose-config:
	docker compose config

docker-up:
	docker compose up --build

docker-down:
	docker compose down

test: api-test lint web-test web-build compose-config
