.PHONY: api-test api-vet web-test web-build compose-config test

api-test:
	go test ./...

api-vet:
	go vet ./...

web-test:
	cd web && npm test

web-build:
	cd web && npm run build

compose-config:
	docker compose config

test: api-test api-vet web-test web-build compose-config
