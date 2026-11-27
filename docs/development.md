# Developing DomainShare

[Back to DomainShare](../README.md)

Run a disposable preview or verify changes against the test domain.

## Repository Layout

- `Dockerfile`
- `docker-compose.yml`
- `setup`
- `.env.example`
- `README.md`
- `app/init.sh`
- `app/reconcile_shares.py`
- `app/access_control.py`
- `app/backup_to_destination.py`
- `app/audit_collector.py`
- `app/audit_store.py`
- `app/state_db.py`
- `app/web_ui.py`
- `app/documents.py`
- `app/document_index.py`
- `app/extract_document.py`
- `app/web/`
- `etc/samba/smb.conf`
- `dev/` (disposable AD DC, backup target, SMB client, seed data, and E2E assertions)
- `scripts/dev`
- `scripts/test-e2e`
- `cmd/domainshare/`, `internal/` (Go backend candidate and SQLite compatibility tests)

## Go Backend Candidate

Use Go 1.25 or newer to run `go test ./...` and `go vet ./...`. Some tests use
Python as a compatibility reference, plus real tools such as 7-Zip, rsync,
Poppler, Tesseract, and `setfacl` when available.

The default image runs the Go backend. Test it with disposable data on a host
with Docker or Podman:

```bash
./scripts/test-e2e
DEV_BACKEND=upgrade ./scripts/test-e2e
DEV_BACKEND=split ./scripts/test-e2e  # requires Docker Compose
```

The first run joins a new test domain with Go. The second starts the legacy
`python-compat` image, then recreates the file server with the default Go image
while retaining the Samba membership, configuration, TLS and data volumes.
Before switching, it uploads a file over SMB, waits for Python to index and
audit it, and creates browser sessions and a scoped agent token. After the
switch, Go must serve that data and preserve the access restrictions. Both
runs then use the same end-to-end suite. Do not run the preview against a live
domain or production volumes.

The split check upgrades the old combined server using `setup` and the real
Compose service definitions on the preview network. It replaces management
while an SMB3 file handle is still open on FSLogix, then reads through the
same handle and checks that Samba was not restarted.

The image also exposes `domainshare backup`,
`domainshare reconcile`, `domainshare trash-cleanup` and `domainshare healthcheck`.
Restore a local encrypted archive into a new directory with
`domainshare-backup restore ARCHIVE NEW_DIRECTORY` (use `--legacy` for an
archive encrypted with the old archive password rather than a recovery phrase).

## Local Preview

Run a complete disposable environment with Docker or Podman:

```bash
./scripts/dev
```

The launcher builds the current application and starts an isolated, run-scoped network containing:

- a real Samba AD DC for `DEV.TEST`, seeded with users, nested groups, and three `FS_*` groups;
- a real Smallstep CA whose ACME provisioner issues the web UI certificate for `files.localhost`;
- an authenticated rsync daemon used by the normal backup implementation;
- the actual file-server image, joined to the dummy domain;
- a continuous SMB client that exercises reads, writes, renames, and deletions, including activity from an excluded dummy service account.

The disposable AD DC is compatible with rootless Podman: its development-only internal ID range stays inside the standard 65,536-entry user namespace, and SYSVOL ACL metadata is stored in `xattr_tdb` because an unprivileged container cannot write the `security.NTACL` namespace. These compatibility settings apply only to `dev/ad-dc.Dockerfile`; the production file-server image and real AD remain unchanged.

The preview starts with group, Private, and FSLogix data. The client keeps current activity moving, while a real backup runs immediately and repeats in the background. Open the URL and use the credentials printed by the launcher. Defaults are:

```text
URL:      https://files.localhost:8443
Username: DEV\previewadmin
Password: PreviewAdmin123!
```

The generated CA is intentionally disposable. `scripts/dev` prints the temporary root certificate path so it can be trusted only for the duration of that run. Ctrl-C stops and removes all run-scoped containers, volumes, the network, and the temporary root. A watchdog performs the same cleanup if the parent script is killed.

To test first-launch onboarding with empty configuration and data, run:

```bash
./scripts/dev --onboarding
```

Open `http://files.localhost:8080/`. This mode starts the same disposable AD, CA, and rsync target, but supplies no application configuration through environment variables and skips file seeding, automatic domain join, the SMB activity client, and the backup driver. Only the external HTTPS port mapping is recorded for correct setup links and browser origin checks.

The launcher prints both setup codes, the ACME directory, the root certificate file to upload, domain credentials, group names, and the optional backup destination. Configure HTTPS first, temporarily trust the disposable CA root, then follow the link to `https://files.localhost:8443/` to complete domain setup. Configure backups afterwards in `/admin/settings`. Each launch starts fresh; Ctrl-C removes that run's configuration and test data. `--onboarding` and `--e2e` are mutually exclusive.

Neither the dummy DC nor the application container receives extra capabilities.

Useful overrides:

| Variable | Default | Purpose |
| --- | --- | --- |
| `DEV_HTTPS_PORT` | `8443` | HTTPS port bound to host loopback |
| `DEV_HTTP_PORT` | `8080` | HTTP setup port bound to host loopback in `--onboarding` mode |
| `DEV_WEB_HOSTNAME` | `files.localhost` | HTTPS name validated by the disposable ACME CA |
| `DEV_SKIP_BUILD` | `0` | Set to `1` to reuse already-built local images |
| `DEV_CA_IMAGE` | `docker.io/smallstep/step-ca:latest` | CA image; pin a tag or digest for reproducible CI |
| `DEV_SERVER_IMAGE` | `domainshare-dev:latest` | Local file-server image name |
| `DEV_AD_IMAGE` | `domainshare-ad-dev:latest` | Local AD/client image name |
| `DEV_BACKUP_IMAGE` | `domainshare-backup-dev:latest` | Local rsync target image name |
| `DEV_REALM` | `DEV.TEST` | Dummy Kerberos realm |
| `DEV_WORKGROUP` | `DEV` | Dummy NetBIOS domain |
| `DEV_DNS_DOMAIN` | `dev.test` | Dummy AD DNS zone |
| `DEV_BASE_DN` | `DC=dev,DC=test` | Dummy directory base DN |
| `DEV_ADMIN_USER` | `previewadmin` | Seeded Domain Admin login |
| `DEV_ADMIN_PASSWORD` | `PreviewAdmin123!` | Seeded Domain Admin password |
| `DEV_USER_PASSWORD` | `PreviewUser123!` | Shared password for seeded non-admin users |
| `DEV_SEED_MB` | `8` | MiB per large seed file |
| `DEV_ACTIVITY_INTERVAL_SECONDS` | `4` | Delay between SMB activity batches |
| `DEV_BACKUP_INTERVAL_SECONDS` | `120` | Delay between completed preview backups |
| `DEV_ARCHIVE_PASSWORD` | `PreviewArchive123!` | Dummy password for encrypted group archives |
| `DEV_BACKUP_AUTO_ENABLED` | `true` | Environment-only automatic-backup setting passed to the file server |

`DEV_REALM`, `DEV_DNS_DOMAIN`, and `DEV_BASE_DN` describe the same domain and must be changed together.

## End-to-End Tests

Run the same disposable stack headlessly with extensive assertions:

```bash
./scripts/test-e2e
```

The E2E suite verifies:

- CA-issued TLS, hostname validation, HSTS, and CSP;
- anonymous rejection, bad credentials, valid non-admin rejection, real Domain Admin login, JWT claims, bearer use, cookie flags, tamper rejection, and logout;
- domain trust, one-time legacy folder/membership migration, and individual folder assignments;
- legacy GUID-path migration with file hash/inode checks, and real container restart after an already-completed access migration;
- individual user assignments, all four SMB access levels, hidden-folder behavior, inheritance, ACL-edit rejection, revocation, and archive/restore;
- SMB allow/deny behavior and real file operations;
- Data, Private, and FSLogix usage aggregation;
- high-level `full_audit` ingestion for all four actions, service-account exclusion, filters, facets, and pagination;
- shared SQLite schema, integrity, indexes, legacy-log removal, and main-read and FSLogix-event deduplication across interleaved events and collector polls;
- real Samba recycle handling plus authenticated trash listing, streamed download, and restore;
- real rsync transfer progress, completed backup status, log output, remote snapshot marker, and per-group encrypted non-solid 7z archives;
- offline Go restore from a completed backup, comparing the recovered file byte for byte in a container with no network or live-data mounts;
- anonymous action rejection plus authenticated manual backup and reconciliation actions, terminal progress, and live reconciliation output;
- overview and system-health aggregation;
- the log-free PDF report snapshot plus local Typst wrapper, WebAssembly, font MIME types, and immutable caching.

The runner returns non-zero on the first failed assertion, prints bounded logs from every run-scoped service, and always removes its containers, volumes, network, and temporary CA root. Set `DEV_SKIP_BUILD=1` for a fast rerun against existing local images.

### Browser checks for access administration

`tests/access_ui_smoke.mjs` drives Chromium with Playwright against the real frontend and a simulated API containing representative folders and 80 AD users. It checks individual permission editing, user search and access filters, unsaved-change protection, failed saves and retries, preserved selection, folder creation, archive/restore, layouts from 390 to 1500 pixels wide, and consistency with the existing admin control styles. It writes desktop and mobile screenshots for visual review.

With Playwright available to Node:

```bash
node tests/access_ui_smoke.mjs
```

`PLAYWRIGHT_MODULE` can point to an external Playwright installation; `PLAYWRIGHT_BROWSERS_PATH` selects its browser cache. `SCREENSHOT_DIR` chooses the screenshot destination; otherwise the runner creates a temporary directory and prints its path. These browser checks use fixture data; `scripts/test-e2e` verifies the real AD/SMB backend.
