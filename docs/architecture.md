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

Desktop and trusted standalone web clients own the complete encrypted snapshot
and global key hierarchy. They synchronize once per minute while open. A community web
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

Private message archives store independent `archive-chunk:<scope>:<chunk-hash>`
vaults, where scope is `full` or `server:<origin-hash>`. The chunk hash is SHA-256
of the local archive identity; message metadata remains inside the ciphertext.
Permissions and encryption keys follow the corresponding settings scope, with
distinct authenticated data for every chunk and revision. Clients gzip at most
100 rows per chunk and process chunks individually. Explicit archive deletions
win over older copies. The `archive:<scope>` vault holds a small version-2 marker;
legacy version-1 snapshots are replaced only after every chunk is uploaded.

`GET /v1/archive/{scope}?after=N&through=M` lists at most 200 changed chunk names,
revisions and sequence numbers. The first response fixes `through` to the current
account sequence; following pages retain that boundary. Vault writes serialize
sequence allocation under the account lock, preventing commit-order gaps.
Clients persist per-chunk revision/digest checkpoints and advance the cursor only
after processing a page set. A separate observed-sequence checkpoint is saved
atomically with each chunk acknowledgement, detecting rollback even between a
partial upload and the next scan. Interrupted uploads retain completed checkpoints.
No aggregate archive-size cap or whole-history manifest is required.

Password changes and recovery start with `paged_vaults: true`. The service records
starting revisions; `GET /v1/recovery/{challenge}/vault` returns one pending vault,
and `PUT /v1/recovery/{challenge}/vault/{scope}` stages its encrypted replacement.
An ordered SHA-256 chain binds every staged ciphertext to the signed finish
request (`staged_vaults: true`). Finalization verifies complete coverage and exact
starting revisions under the account lock, then atomically replaces all payloads,
advances their change sequences, rotates credentials and revokes old devices.
Staging expires after 15 idle minutes. Abandoned stages never
change current vaults and expire with their challenge. Legacy inline migrations
retain their 256-vault/128 MiB request bounds; paged migrations have no such
aggregate request or vault-count limit.

`GET /v1/vault/{scope}?known_revision=N` returns
`{ "revision": N, "ciphertext": null, "unchanged": true }` when the revision
matches. The query avoids reading or transferring the ciphertext in that case.
A changed revision returns the encrypted snapshot as usual.

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
- `/v1/archive/*` for paged archive changes.
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
