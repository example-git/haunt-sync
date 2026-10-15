# syntax=docker/dockerfile:1
FROM golang:1.26.9-alpine3.23 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then export SSL_CERT_FILE=/run/secrets/proxy_ca; fi; go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG TARGETARCH
ARG VERSION=development
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} GOPROXY=off go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /haunt-sync ./cmd/haunt-sync
FROM cloudflare/cloudflared:2026.10.0 AS tunnel
FROM postgres:16-alpine
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /haunt-sync /usr/local/bin/haunt-sync
COPY --from=tunnel /usr/local/bin/cloudflared /usr/local/bin/cloudflared
RUN --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then export SSL_CERT_FILE=/run/secrets/proxy_ca; fi; \
    apk add --no-cache python3 && \
    addgroup -g 65532 haunt && adduser -D -H -u 65532 -G haunt haunt && \
    mkdir -p /data/updates && chown -R 65532:65532 /data
COPY deploy/entrypoint.py /usr/local/bin/haunt-sync-start
USER 65532:65532
ENV HAUNT_SYNC_LISTEN_ADDR=127.0.0.1:8090
VOLUME ["/data"]
ENTRYPOINT ["python3", "/usr/local/bin/haunt-sync-start"]
