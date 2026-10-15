# Development

## Toolchains

- Go 1.26.9 or newer.
- PostgreSQL 16 for database-backed integration tests.
- Node.js and an installed Haunt Client checkout for real browser/Go protocol
  verification.
- Docker for the complete bundled-container checks.

Build the standalone service with:

```sh
go build ./cmd/haunt-sync
```

## Fast checks

Run before submitting ordinary changes:

```sh
gofmt -w cmd internal
go test ./...
go vet ./...
python3 scripts/check-repository.py
python3 scripts/check-docs.py
```

Tests that need external fixtures skip when their explicit environment is absent.
A passing fast suite does not establish end-to-end restore behavior.

## Database and browser integration

Use a dedicated PostgreSQL 16 database at `127.0.0.1:32768`, conventionally
named `haunt_sync_iteration`. Never point tests at a personal or production
database.

Set:

```sh
export HAUNT_SYNC_TEST_DATABASE_URL='postgres://USER:PASSWORD@127.0.0.1:32768/haunt_sync_iteration?sslmode=disable'
export HAUNT_SYNC_CLIENT_CHECKOUT='/path/to/haunt-client'
go test -race ./... -count=1 -timeout 180s
```

The integration test creates a disposable schema, launches the real browser
OPAQUE library against production Go handlers, and checks registration, login,
tamper rejection, encrypted storage, and synthetic plaintext absence. Rendered
checks additionally require a disposable Haunt community fixture and a built
web client.

Use only synthetic accounts and isolated browsers.

## Container verification

Coordinated container verification lives in the
[Haunt hub](https://github.com/example-git/haunt). It builds the exact pinned
sync and client commits, runs the real browser protocol suite, checks the
all-in-one image on amd64 and arm64, and verifies restart and tunnel-mode
behavior.

This repository's CI intentionally provides fast standalone feedback. Changes
to `Dockerfile`, `compose*.yml`, `deploy/`, `mail-relay/`, or cross-client
protocol behavior also require the hub checks before release.

## Repository hygiene

`scripts/check-repository.py` verifies that private configuration, credentials,
database files, test results, build output, and local agent/editor state remain
ignored while required source files remain trackable.

History scanning in CI uses Gitleaks. The documentation checker validates local
Markdown links without requiring external network access.

## Change boundaries

- Authentication, proof binding, vault revisions, recovery, or pairing changes
  require adversarial tests and updates to [Security](security.md).
- Configuration or lifecycle changes require updates to
  [Deployment](deployment.md) and [Operations](operations.md).
- SMTP changes require transport tests and updates to [Mail](mail.md).
- Update-serving changes require hash, range, path-traversal, and concurrency
  tests plus updates to [Updates](updates.md).
- Cross-repository protocol changes must update the hub
  [implementation contract](https://github.com/example-git/haunt/blob/main/docs/sync-service.md).

## Required end-to-end outcomes

Before calling a release path verified, exercise real browser/Go registration
and login, wrong-password and transcript-tamper rejection, encrypted upload and
fresh-client restore, database inspection for synthetic plaintext credentials,
concurrent users and revisions, indefinite sessions, logout and revocation,
PKCE mismatch and replay, redirect manipulation, origin forgery, key
substitution, and cross-scope denial.

Unit tests alone do not establish those outcomes.
