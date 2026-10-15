# Security policy

Haunt Sync and its Go OPAQUE implementation have not received an independent
security audit. The service stores encrypted snapshots and authentication
records, but operators can still observe metadata and withhold, replay, or
corrupt ciphertexts. Review the hub's
[implementation contract](https://github.com/example-git/haunt/blob/main/docs/sync-service.md)
before relying on the service.

## Supported versions

Security fixes target the current `main` branch and the newest coordinated Sync
image. Older instances should be upgraded with their complete persistent
database and identity material intact.

## Reporting a vulnerability

Use this repository's GitHub **Report a vulnerability** feature. If it is
unavailable, contact a repository owner privately. Do not open a public issue
for a suspected vulnerability.

Include the affected commit, impact, protocol transcript using synthetic data,
reproduction steps, and mitigation if known. Never submit real passwords,
keywords, tokens, recovery keys, snapshots, SMTP credentials, or tunnel tokens.
The project does not currently promise a response SLA or bug bounty.
