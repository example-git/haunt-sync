![Haunt](assets/haunt-wordmark.png)

# Haunt Sync

Haunt Sync is an optional, independently hosted service for synchronizing
encrypted Haunt settings and saved sign-ins across a user's devices. A group can
run its own instance without creating a project-wide account service or coupling
sync availability to any community server.

Clients remain the working copy. The service stores current encrypted snapshots
and wrapped keys; it cannot decrypt them, and it is not an archival backup.
Ordinary Haunt sign-in continues to work when sync is disabled or unavailable.

## Choose a starting point

| Goal | Documentation |
| --- | --- |
| Run the recommended container with a stable public address | [Named-tunnel deployment](docs/deployment.md#named-cloudflare-tunnel) |
| Try a disposable instance | [Quick Tunnel](docs/deployment.md#disposable-quick-tunnel) |
| Run the Go binary with your own PostgreSQL and HTTPS gateway | [Standalone deployment](docs/deployment.md#standalone-binary) |
| Operate, back up, upgrade, or troubleshoot an instance | [Operations](docs/operations.md) |
| Configure email verification | [Mail delivery](docs/mail.md) |
| Mirror signed desktop updates | [Update distribution](docs/updates.md) |
| Understand keys, pairing, sessions, and recovery | [Security model](docs/security.md) |
| Understand the service and repository | [Architecture](docs/architecture.md) |
| Build and test changes | [Development](docs/development.md) |
| Browse every guide | [Documentation index](docs/index.md) |

## Recommended deployment

The supplied Compose project runs Haunt Sync, PostgreSQL, and Cloudflare Tunnel
inside one hardened container. It publishes no host ports; the database and API
listen only on loopback inside the container.

```sh
cp .env.example .env
chmod 600 .env
# Set HAUNT_SYNC_HOST and HAUNT_SYNC_TUNNEL_TOKEN.
docker compose --project-name haunt-nexus pull
docker compose --project-name haunt-nexus up -d
```

Use a remotely managed named tunnel for a stable instance. Quick Tunnel mode is
deliberately temporary and starts with an empty disposable database after a full
restart. Read the [deployment guide](docs/deployment.md) before choosing between
them.

The published image is `ghcr.io/example-git/haunt:sync-latest` for Linux amd64
and arm64. Keep sync data and community-server data in separate projects and
volumes.

## Trust boundary

- Master passwords, private sync keywords, payload keys, and plaintext snapshots
  stay in trusted client code.
- The service stores OPAQUE authentication records, encrypted vaults, wrapped
  keys, device metadata, and revision state.
- Email can restore account access but cannot decrypt an existing snapshot by
  itself.
- Community-hosted browsers receive only their origin's key through pairing;
  trusted standalone clients can sign in for full-account sync.
- Operators can observe metadata and can withhold, corrupt, or replay
  ciphertexts. The Go OPAQUE implementation has not received an independent
  security audit.

The complete model, limitations, and recovery behavior are in
[Security](docs/security.md). Protocol requirements are recorded in the hub's
[implementation contract](https://github.com/example-git/haunt/blob/main/docs/sync-service.md).

## Repository layout

| Path | Responsibility |
| --- | --- |
| `cmd/haunt-sync/` | Standalone service entry point and TLS/listener policy |
| `internal/protocol/` | OPAQUE protocol adapter |
| `internal/service/` | Authentication, devices, vaults, mail, updates, schema, and HTTP routes |
| `deploy/` | All-in-one container supervisor and tunnel configuration |
| `mail-relay/` | Optional private Postfix/OpenDKIM relay |
| `tests/` | Cross-component container/browser checks |
| `docs/` | Operator, security, architecture, and development guides |
| `scripts/` | Repository and documentation validation |

## Verification

The fast standalone checks are:

```sh
go test ./...
go vet ./...
python3 scripts/check-repository.py
python3 scripts/check-docs.py
```

Database-backed browser integration and complete container checks require the
isolated fixtures described in [Development](docs/development.md). CI runs the
standalone checks for every pull request.

## License and participation

Haunt-owned code in this repository is available under the
[BSD 3-Clause License](LICENSE). See [CONTRIBUTING.md](CONTRIBUTING.md) before
submitting changes and [SECURITY.md](SECURITY.md) for private vulnerability
reports.
