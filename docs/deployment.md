# Deployment

Choose a stable named tunnel for normal use, Quick Tunnel only for disposable
evaluation, or the standalone binary when you already operate PostgreSQL and an
HTTPS gateway.

## Deployment matrix

| Mode | Public address | Database | Persistence | Intended use |
| --- | --- | --- | --- | --- |
| Named Cloudflare Tunnel | Stable operator hostname | Bundled PostgreSQL | Named Docker volume | Recommended |
| Quick Tunnel | Random `trycloudflare.com` address | Temporary bundled database | Discarded after full restart | Evaluation |
| Standalone binary | Operator-managed HTTPS origin | External PostgreSQL | Operator-managed | Existing infrastructure |

## Named Cloudflare Tunnel

The published image is
`ghcr.io/example-git/haunt:sync-latest` for Linux amd64 and arm64. It contains
Haunt Sync, PostgreSQL, and cloudflared. No host ports are published.

1. Create a remotely managed named tunnel, such as `haunt-nexus`.
2. Add a public hostname whose service is `http://127.0.0.1:8090`.
3. Copy the example environment and protect it:

   ```sh
   cp .env.example .env
   chmod 600 .env
   ```

4. Set `HAUNT_SYNC_HOST` to the hostname only, without a scheme or path.
5. Set `HAUNT_SYNC_TUNNEL_TOKEN` to the named-tunnel token.
6. Start the dedicated project:

   ```sh
   docker compose --project-name haunt-nexus pull
   docker compose --project-name haunt-nexus up -d
   ```

The entrypoint writes the tunnel token atomically to
`/data/run/cloudflared-token` with mode `0600` and gives cloudflared only the
file path. After changing `.env`, rerun `docker compose up -d` so Compose
recreates the container with the new environment. A simple restart retains the
old environment.

The bundled database password is generated at first startup and saved privately
under `/data`. An optional `HAUNT_SYNC_DB_PASSWORD` must contain 32–256
URL-safe characters and must match the saved password on every later start.

### Container environment reference

| Variable | Required | Meaning |
| --- | --- | --- |
| `HAUNT_SYNC_IMAGE` | No | Image reference; defaults to `ghcr.io/example-git/haunt:sync-latest` |
| `HAUNT_SYNC_HOST` | Named mode | Public hostname without a scheme or path |
| `HAUNT_SYNC_TUNNEL_TOKEN` | Named mode | Remotely managed Cloudflare tunnel token |
| `HAUNT_SYNC_QUICK_TUNNEL` | No | Must be exactly `true` to select disposable mode |
| `HAUNT_SYNC_DB_PASSWORD` | No | Optional fixed bundled-database password |
| `HAUNT_SYNC_UPDATES_PATH` | No | Host directory containing verified update releases |
| `HAUNT_SYNC_SMTP_*` | No | Optional mail transport; see [Mail](mail.md) |

## Disposable Quick Tunnel

Set no tunnel token and explicitly choose:

```dotenv
HAUNT_SYNC_QUICK_TUNNEL=true
```

Startup prints a random `trycloudflare.com` HTTPS issuer. With the bundled
database, each full container launch uses a fresh temporary database. After a
restart, clients must select the new address, create a new sync account, and
upload their existing local settings.

Quick mode does not erase the named-tunnel database under `/data/postgres`.
It uses a separate temporary directory and removes it during orderly shutdown.
An external persistent database will reject the changed random issuer. A token
and Quick Tunnel mode cannot be enabled together.

## Standalone binary

Build with Go 1.26.9 or newer:

```sh
go build ./cmd/haunt-sync
```

The database user needs permission to create the configured schema. At minimum:

```sh
HAUNT_SYNC_DATABASE_URL='postgres://USER:PASSWORD@127.0.0.1/haunt_sync' \
HAUNT_SYNC_ISSUER='https://nexus.your-domain.example' \
./haunt-sync
```

The default listener is `127.0.0.1:8090`. Keep it on loopback behind an HTTPS
proxy, or set both `HAUNT_SYNC_TLS_CERT` and `HAUNT_SYNC_TLS_KEY` for a
non-loopback TLS 1.3 listener. Plaintext external listeners are refused.

### Standalone environment reference

| Variable | Required | Meaning |
| --- | --- | --- |
| `HAUNT_SYNC_DATABASE_URL` | Yes | Dedicated PostgreSQL connection |
| `HAUNT_SYNC_ISSUER` | Yes | Canonical public HTTPS origin, without a path |
| `HAUNT_SYNC_LISTEN_ADDR` | No | Listener; defaults to `127.0.0.1:8090` |
| `HAUNT_SYNC_SCHEMA` | No | PostgreSQL schema; defaults to `haunt_sync` |
| `HAUNT_SYNC_TLS_CERT` / `HAUNT_SYNC_TLS_KEY` | Together | Direct TLS certificate and private key |
| `HAUNT_SYNC_TRUSTED_PROXIES` | No | Comma-separated proxy CIDRs allowed to supply forwarding headers |
| `HAUNT_SYNC_UPDATES_DIR` | No | Read-only directory containing a verified update mirror |
| `HAUNT_SYNC_ALLOW_LOOPBACK_HTTP` | Tests only | Allows an HTTP loopback issuer for isolated verification |
| `HAUNT_SYNC_SMTP_*` | No | Optional mail transport; see [Mail](mail.md) |

The issuer and OPAQUE server identity are stored in PostgreSQL. Preserve the
complete database when moving an instance. Changing the issuer is not a rename
operation.

## Cloudflare and reverse-proxy rules

For the bundled tunnel:

- Leave Cloudflare Access login and browser challenges off API routes.
- Bypass cache for `/v1/*`.
- Only public `/client-updates/*` responses may be cached.
- Keep cloudflared at normal log verbosity; debug logs can expose headers.
- Verify `/v1/config` through the public hostname before connecting clients.

For a standalone reverse proxy, set `HAUNT_SYNC_TRUSTED_PROXIES` to the exact
proxy network. Never use an unrestricted CIDR merely to make forwarded headers
work.

## Health check

`GET /healthz` returns success only after the service can use PostgreSQL.
Compose checks it through loopback. A healthy local container does not prove the
public tunnel, DNS, certificate, or client route works; verify `/v1/config`
through the public origin as a separate step.

Continue with [Operations](operations.md) for persistence, upgrades, and
recovery.
