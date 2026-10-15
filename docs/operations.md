# Operations

Haunt Sync is designed so a service outage does not erase local client state.
Operators are still responsible for preserving instance identity, encrypted
snapshots, and configuration when continuity matters.

## Persistent state

The named-tunnel container stores all persistent state in the `sync_data`
volume:

- `/data/postgres`: PostgreSQL data, including accounts, encrypted vaults,
  OPAQUE identity, and issuer binding.
- `/data/database-password`: generated bundled-database credential.
- `/data/run`: regenerated runtime files such as the tunnel-token file.
- `/data/updates`: default internal update directory; Compose normally mounts
  the configured host mirror at `/updates` instead.

Keep this volume separate from every Haunt community-server volume. Never mount
an existing PostgreSQL data directory from another application into the bundle.

Standalone installations must preserve their complete PostgreSQL database.
Copying selected tables is not a supported migration because configuration and
OPAQUE key material are part of instance identity.

## Backups

Sync is not itself an archival backup. Clients should keep deliberate encrypted
client backups even when the service database is protected.

For a consistent service backup:

1. Stop writes or use PostgreSQL's supported consistent-backup tooling.
2. Preserve the complete database, not only vault rows.
3. Preserve the instance's configured issuer and deployment records.
4. Protect backup media as account metadata and encrypted payload storage.
5. Test restoration into an isolated environment before relying on it.

For the all-in-one image, use a named-volume backup method appropriate to the
container host. Stop the Compose project for a simple cold backup. Do not copy a
live PostgreSQL directory file by file.

## Restore and migration

Restore the database and its saved bundled password together. Start the service
with the same issuer. The service rejects an issuer mismatch rather than silently
creating a second identity over existing data.

To move a named-tunnel instance:

1. Preserve the complete `sync_data` volume.
2. Preserve or deliberately rotate the Cloudflare named-tunnel token.
3. Keep the public hostname unchanged.
4. Recreate the Compose project and verify `/healthz` locally.
5. Verify `/v1/config` through the public hostname.
6. Confirm an existing client can authenticate and read its current revision.

A new hostname is a new sync instance from the client's perspective. Publish
local state from an existing unlocked client instead of rewriting an established
issuer in place.

## Upgrades

Pin `HAUNT_SYNC_IMAGE` to a coordinated version when repeatability matters.
Before upgrading:

- Read release notes for database or protocol changes.
- Take and verify a complete backup.
- Pull the new image without deleting the named volume.
- Recreate the container and watch its startup logs.
- Verify both local health and the public configuration endpoint.
- Confirm one existing client can synchronize.

The entrypoint supervises PostgreSQL, the Go service, and cloudflared. If any
child exits, it stops the whole bundle visibly. Orderly shutdown lets the service
finish requests before PostgreSQL checkpoints and exits.

## Health and diagnostics

Use:

```sh
docker compose --project-name haunt-nexus ps
docker compose --project-name haunt-nexus logs --tail 200 nexus
```

Check failures in this order:

1. Container health and the first startup error.
2. Database readiness.
3. `http://127.0.0.1:8090/healthz` inside the runtime boundary.
4. Tunnel connectivity and DNS.
5. Public `/v1/config`.
6. Client issuer selection and local clock.

Startup errors intentionally avoid printing credential values or child-process
arguments. Do not enable verbose tunnel logging in production merely to inspect
requests.

## Common failure modes

| Symptom | Likely cause |
| --- | --- |
| Startup refuses an empty token | Neither a named token nor explicit Quick mode was selected |
| Saved database password mismatch | `HAUNT_SYNC_DB_PASSWORD` changed for an existing volume |
| Issuer mismatch | Existing database started under a different public origin |
| Local health works but clients fail | Tunnel, DNS, TLS, Cloudflare policy, or cache configuration |
| Email actions fail but password login works | SMTP is unset or delivery failed |
| Update feed reports unavailable | No verified release has been imported |
| Quick URL changed and accounts disappeared | Expected disposable Quick Tunnel restart |

## Retention and loss

The service stores current revisions and does not promise archival history or
operator recovery of plaintext. Losing the instance cannot remove local client
data, but data held only by that instance is unrecoverable.

Users can select a replacement instance, create an account, and upload from an
existing client. See [Security](security.md) for the client recovery boundary.
