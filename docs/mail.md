# Mail delivery

Email verification is optional. Username/master-password sign-in continues to
work when SMTP is unconfigured or delivery fails. Email can restore account
access but cannot decrypt existing snapshots without client-held recovery
material.

Verification links are one-use, expire after ten minutes, and are bound to the
requesting device's proof key. Users should copy a link into the Haunt window
that requested it.

## Existing SMTP service

Configure:

| Variable | Meaning |
| --- | --- |
| `HAUNT_SYNC_SMTP_HOST` | SMTP hostname |
| `HAUNT_SYNC_SMTP_PORT` | Port; defaults to 587 |
| `HAUNT_SYNC_MAIL_FROM` | Valid sender address |
| `HAUNT_SYNC_SMTP_USERNAME` | Optional authentication username |
| `HAUNT_SYNC_SMTP_PASSWORD` | Optional authentication password |
| `HAUNT_SYNC_SMTP_CA_FILE` | Optional private CA certificate |

Port 465 uses direct TLS. Other ports must offer STARTTLS. Certificates are
always verified and TLS cannot be disabled. Mount a private relay's public CA
certificate read-only when using `HAUNT_SYNC_SMTP_CA_FILE`.

Do not expose or configure an unauthenticated public relay.

## Optional local send-only relay

`compose.mail.yml` adds a private Postfix/OpenDKIM relay to the same Nexus
project. It publishes no ports or inbox, accepts only the project's private
network and configured sender, and requires TLS for submissions and outbound
delivery.

Set these values in the protected `.env` file:

```dotenv
COMPOSE_FILE=compose.yml:compose.mail.yml
HAUNT_SYNC_MAIL_FROM=haunt@your-domain.example
HAUNT_SYNC_MAIL_HOST=mail.nexus.your-domain.example
HAUNT_SYNC_MAIL_DOMAIN=your-domain.example
HAUNT_SYNC_MAIL_TRUSTED_NETWORK=YOUR_EXACT_PROJECT_NETWORK_CIDR
HAUNT_SYNC_MAIL_TLS_PATH=../.local/sync-mail/tls
HAUNT_SYNC_MAIL_DKIM_PATH=../.local/sync-mail/dkim
```

The TLS directory must contain `ca.crt`, `server.crt`, and `server.key`.
The certificate must cover `mailer` and `localhost`. The DKIM directory must
contain the RSA signing key `haunt.private`; the selector is `haunt`. Keep
private keys outside Git with mode `0600`.

Start both Compose files:

```sh
docker compose --project-name haunt-nexus \
  -f compose.yml -f compose.mail.yml up -d --build
```

Keeping `COMPOSE_FILE=compose.yml:compose.mail.yml` in `.env` preserves the
selection for ordinary Compose commands.

## DNS and delivery requirements

Direct outbound mail requires:

- Outbound TCP port 25.
- A stable public sending IP.
- A DNS-only A record for the sending hostname.
- SPF authorizing that IP.
- A `haunt._domainkey` TXT record containing the DKIM public key.
- An appropriate DMARC policy for the sender domain.

Cloudflare Tunnel does not deliver SMTP.
Undeliverable messages expire from the relay queue after ten minutes.

Container health checks local SMTP readiness. Verify end-to-end delivery by
sending a verification message to a controlled recipient.
