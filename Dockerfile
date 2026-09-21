FROM node:22-alpine AS web-build
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.22-alpine AS api-build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/cert-harbor ./cmd/cert-harbor

FROM alpine:3.22
RUN addgroup -S certharbor && adduser -S -G certharbor certharbor
COPY --from=api-build /out/cert-harbor /app/cert-harbor
COPY --from=web-build /src/web/dist /app/web
RUN chown -R certharbor:certharbor /app
USER certharbor
ENV CERT_HARBOR_ADDR=0.0.0.0:8080
ENV CERT_HARBOR_WEB_DIR=/app/web
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1
ENTRYPOINT ["/app/cert-harbor"]
