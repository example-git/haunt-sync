# Contributing

This repository owns the optional Haunt Sync service, its OPAQUE authentication
implementation, encrypted snapshot storage, browser-pairing grants, mail
integration, and standalone container definition. Client-side encryption and
user interfaces live in Haunt Client; coordinated images and integration checks
live in the Haunt hub.

## Before submitting a change

- Preserve the documented boundary: passwords, private keywords, payload keys,
  and plaintext snapshots do not belong on the service.
- Add protocol and tamper tests for authentication or authorization changes.
- Use only disposable test databases and synthetic accounts.
- Update the implementation contract in the hub when security behavior changes.

Run:

```sh
go test ./...
python3 scripts/check-docs.py
```

The full browser/Go and container checks require the isolated fixtures described
in [Development](docs/development.md#database-and-browser-integration). Report vulnerabilities through the private process in
[SECURITY.md](SECURITY.md), not in a public issue.
