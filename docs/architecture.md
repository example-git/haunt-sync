# Architecture

Haunt Sync is separate from every Haunt community server. It coordinates
encrypted client state; it does not federate communities, host a project-wide
identity, or become a dependency for ordinary community sign-in.

## Components and data flow

```text
Haunt desktop ── OPAQUE + proof-bound session ──┐
                                                │
Community web client ── scoped pairing grant ───┼── Haunt Sync ── PostgreSQL
                                                │
Desktop updater ── public signed downloads ─────┘
```

The desktop client owns the complete encrypted snapshot and global key hierarchy.
A signed-in desktop synchronizes once per minute while open. A community web
client can receive only the key for its exact HTTPS origin after
approval from an unlocked desktop. The public update feed is independent of sync
accounts and contains already signed release artifacts.

## Service responsibilities

The Go service provides:

- OPAQUE registration and login.
- Proof-bound device sessions and revocation.
- Revisioned encrypted vault storage.
- Desktop-approved OAuth-style browser pairing with S256 PKCE.
- Email verification and account-recovery coordination when SMTP is configured.
- Atomic password/private-keyword migration records.
- Optional public distribution of signed desktop update files.
- Health and public configuration endpoints.

The service never receives the master password, private sync keyword, derived
payload root, plaintext settings, or community credentials.

## Storage model

PostgreSQL stores service identity, accounts, OPAQUE records, device token
hashes, proof keys, encrypted vaults, pairing authorizations, replay protection,
rate limits, and email challenges. The service creates one configurable schema,
`haunt_sync` by default.

Vaults are keyed by account and scope and use monotonically increasing revisions.
Concurrent writes compare the expected revision. Independent edits can merge in
the client; competing edits require an explicit user decision instead of silent
last-write-wins replacement.

The issuer and OPAQUE server identity are persistent instance identity. Changing
the issuer on an existing database is not a rename operation and is rejected.

## HTTP surface

Public discovery and health:

- `GET /healthz`
- `GET /v1/config`
- `GET /.well-known/oauth-authorization-server`

API families:

- `/v1/auth/*` for OPAQUE registration and login.
- `/v1/vault/*` and `/v1/vaults` for encrypted snapshots.
- `/v1/devices/*` for device listing and revocation.
- `/v1/oauth/*` for browser pairing.
- `/v1/email/*` and `/v1/recovery/*` for optional verified recovery.
- `/client-updates/*` for the unauthenticated signed-update mirror.

The implementation contract lives in the
[Haunt hub](https://github.com/example-git/haunt/blob/main/docs/sync-service.md);
routes and schema remain owned by this repository.

## Runtime forms

The standalone binary expects an external PostgreSQL database and either a
loopback listener behind an HTTPS gateway or its own TLS 1.3 certificate and key.

The all-in-one image supervises a private PostgreSQL process, the Go service, and
Cloudflare Tunnel. It forces the API and database onto loopback, drops Linux
capabilities through Compose, runs as UID 65532, and persists instance data under
`/data`.

## Repository ownership

- `cmd/haunt-sync` owns process startup, listener safety, and graceful shutdown.
- `internal/protocol` owns the Go/browser OPAQUE compatibility layer.
- `internal/service` owns validation, persistence, routes, and security checks.
- `deploy` owns bundled database and tunnel lifecycle.
- `mail-relay` owns the optional private outbound relay.
- Client-side encryption and interfaces live in
  [haunt-client](https://github.com/example-git/haunt-client).
- Coordinated images and end-to-end release checks live in the
  [Haunt hub](https://github.com/example-git/haunt).
