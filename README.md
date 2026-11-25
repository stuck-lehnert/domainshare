# DomainShare

DomainShare is a self-hosted SMB file server for an existing Active Directory domain. It runs Samba in Docker and adds a web portal for finding files and managing access.

## Features

- Private home folders, shared Data folders, and an FSLogix profile share.
- AD sign-in and per-user folder permissions managed in the browser.
- Full-text file search, including OCR for scanned PDFs.
- File activity logs, a seven-day recycle bin, and scheduled remote backups with optional encryption.

## Quick start

You need Docker with Compose, a reachable AD domain and an account allowed to join it, and an ACME certificate authority that can resolve your HTTPS hostname and reach it on port 80.

```sh
git clone https://github.com/stuck-lehnert/domainshare.git
cd domainshare
./setup
docker compose logs samba
```

Open `http://<server>/` and enter the HTTPS setup code from the logs. Once your certificate is ready, follow the HTTPS link and use the separate setup code to join the domain and select access groups.

## Try it locally

Run `./scripts/dev` with Docker or Podman. It starts a disposable AD domain and prints the preview URL and credentials.

## Documentation

- [Operations](docs/operations.md) — configuration, upgrades, backups, and troubleshooting.
- [Architecture](docs/architecture.md) — Samba integration, document search, and activity storage.
- [Development](docs/development.md) — local preview, test commands, and browser checks.

## License

[GNU Affero General Public License v3](LICENSE).
