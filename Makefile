.PHONY: api-test api-vet api-race lint web-test web-build compose-config test

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

test: api-test lint web-test web-build compose-config
