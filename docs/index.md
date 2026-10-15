# Haunt Sync documentation

Haunt Sync documentation is organized by task and audience.

## Operators

- [Deployment](deployment.md): choose a named tunnel, disposable Quick Tunnel,
  or standalone service.
- [Operations](operations.md): persistence, backups, upgrades, health checks,
  and failure recovery.
- [Mail delivery](mail.md): existing SMTP services and the optional local
  send-only relay.
- [Signed update distribution](updates.md): mirror verified Haunt desktop
  releases without exposing credentials.

## Security and design

- [Security model](security.md): secrets, encrypted storage, browser pairing,
  sessions, migrations, recovery, and explicit limitations.
- [Architecture](architecture.md): components, request surface, storage model,
  and repository ownership.
- [Hub implementation contract](https://github.com/example-git/haunt/blob/main/docs/sync-service.md):
  cross-repository protocol requirements and verification expectations.

## Contributors

- [Development](development.md): toolchains, tests, fixtures, and change
  boundaries.
- [Contributing](../CONTRIBUTING.md): submission expectations.
- [Security policy](../SECURITY.md): private vulnerability reporting.
