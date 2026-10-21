# Security model

Haunt Sync stores encrypted current state for transfer between clients. It does
not make an untrusted client trustworthy, provide an archival history, or hide
all metadata from the operator. The service and its Go OPAQUE implementation
have not received an independent security audit.

## Secrets and encrypted payloads

Trusted-client sign-in uses a master password and a private sync keyword. Neither value,
nor the locally computed keyword salt or encryption root, is sent to the
service.

Clients derive a deterministic 256-bit root with Argon2id v1.3 using 64 MiB,
three iterations, and four lanes. Spaces and case in the private keyword are
significant; choose a long private word or phrase. The account name is separate
and is not a payload key. The keyword contributes a local SHA-256 salt under a
fixed versioned domain. Domain-separated keys derived from the resulting root
wrap recovery material and encrypt full or per-origin snapshots with
AES-256-GCM. Ciphertexts authenticate the account, issuer, scope, and revision.

OPAQUE follows RFC 9807 with matching Ristretto255/SHA-512 parameters. Its AKE
session key is shared with the service and is never reused as a payload key.
Stored device tokens are hashed.

## Desktop and browser boundaries

Electron and the dedicated standalone web client hold the full encrypted
snapshot and can synchronize multiple community accounts. Actions builds trust
the standalone client's published origin; operators can explicitly configure
additional trusted origins. The standalone application's host supplies its code
and must be trusted with the full client key hierarchy. A community-hosted web
client can synchronize only its own canonical HTTPS origin.

For browser pairing:

1. The browser creates an exchange key and proof key and displays a request.
2. The user copies that request to an unlocked desktop.
3. Desktop displays the sync instance, community origin, and fingerprint.
4. After user approval, desktop wraps only that origin's key to the browser's
   public exchange key.
5. The browser redeems the approval with S256 PKCE and its proof key.

The browser's private keys never leave that browser. Neither secret nor the
global root is entered on or delivered to a community page. A compromised
community client can read its approved scope, but not another origin or the full
desktop snapshot through this protocol.

## Sessions and proof binding

Established sync sessions do not expire solely because time passes. They are
bound to device proof keys and end through logout, recovery, credential changes,
or explicit device revocation. Authentication challenges, proof freshness, and
authorization codes remain short-lived and one-use.

Logout removes local vault keys immediately. If remote revocation cannot finish
while offline, the client retains only the proof-bound token needed to retry
that revocation. Community-server sessions retain their own expiration and
revocation policies; sync does not extend them.

TLS protects transport. Public issuers require canonical HTTPS origins.
Standalone plaintext listeners are restricted to loopback. Proxy forwarding
headers are accepted only from explicitly configured CIDRs. Redirects, OAuth
clients, origins, PKCE values, and proof replays are validated exactly.

## Password and keyword changes

Changing either secret first synchronizes pending local edits. The client then
re-encrypts every stored snapshot and recovery envelope, rotates the recovery
signing key, and submits a signed complete migration.

The service commits authentication and ciphertext changes together only if all
current revisions match. It revokes other devices and in-flight challenges in
the same operation. The initiating client then uploads a complete snapshot and
all server scopes, including unchanged data.

A lost commit acknowledgement is reported as uncertain; the client stops using
the old session and asks the user to verify the new credentials. An interrupted
resynchronization remains visibly incomplete until retried. Migration requests
have a 128 MiB total limit.

## Email and recovery

Email is optional. A verified email can restore account access, but decrypting
an existing snapshot still requires one of:

- The exact master password and private sync keyword.
- The offline recovery key.
- An already unlocked trusted device.

Email links are one-use, expire after ten minutes, and are bound to the
requesting device's proof key. Copy a link into the Haunt window that requested
it. There is no operator recovery key, and neither a mail provider nor a service
operator can turn email recovery into a payload-decryption path.

## Operator capabilities and limitations

The operator can observe account metadata, ciphertext size, timing, device
records, and network information. The operator can deny service or return old,
corrupt, or missing ciphertext. A newly installed client has no independent
revision history with which to detect every rollback.

The operator does not receive payload keys through the intended protocol.
However, malware, a compromised trusted client, weak or guessed secrets, and
incorrect client builds are outside an absolute confidentiality guarantee.

## Availability and backup boundary

Clients remain usable without the sync service. Losing the service does not
delete their local settings. A user can select a replacement service and publish
from an existing unlocked client.

Data that exists only on the lost sync instance cannot be recovered. Sync keeps
current encrypted state, not archival history; users still need deliberate
encrypted client backups for disaster recovery.

Client backups have a 20 MiB plaintext limit. That limit is separate from the
128 MiB complete credential-migration request limit.
