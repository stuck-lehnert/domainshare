# AD-Integrated Containerized Samba File Server

This repository provides a production-oriented Samba file server container that joins an existing Active Directory domain and exposes three SMB shares: `Private`, `Data`, and `FSLogix`.

## Architecture

- Samba runs in ADS mode with `winbind` identity mapping.
- Static shares:
  - `\\server\Private` -> `/data/private`
  - `\\server\Data` -> `/data/groups/data`
  - `\\server\FSLogix` -> `/data/fslogix`
- FS_* groups are projected as folders inside the Data share (`/data/groups/data/<groupName>`).
- Data folder ACLs expand nested AD group membership recursively, resolve groups by SID, include `primaryGroupID` membership, and detect group cycles.
- Group records, normalized activity events, collector offsets, and web caches share one SQLite database at `/state/shares.db`.
- Group folders are name-based while active and moved to archive on deactivation:
  - active: `/data/groups/data/<groupName>`
  - inactive/deleted groups: `/data/groups/archive/<groupName>`
- Samba machine trust/key material is persisted in `/var/lib/samba` to survive container recreation.
- Container hostname is fixed (`SAMBA_HOSTNAME`) to keep AD computer identity stable.
- In bridge-mode Docker networking, startup can publish the host LAN IP in AD DNS with `AD_DNS_IP`/`AD_DNS_NAME` instead of the container bridge IP.
- NetBIOS name defaults to `ADSAMBAFSRV` and is clamped to 15 characters (`NETBIOS_NAME` override supported).
- Setup prompts for well-known authorization groups by SID (`DOMAIN_USERS_SID`, `DOMAIN_ADMINS_SID`) to avoid localized group names.
- `FSLOGIX_GROUP_SID` controls who can access the default FSLogix share (defaults to `DOMAIN_USERS_SID`).
- Startup resolves those SIDs to NSS group names via winbind, then uses those resolved groups in Samba `valid users` rules.
- Samba `full_audit` is restricted to successful and failed reads, writes, renames, and deletions.
- A collector normalizes those four actions and persists them in indexed SQLite tables; activity is never automatically deleted.
- A plain HTTPS administration console provides read-only statistics and logs plus narrowly scoped actions for manual backups and share reconciliation. It also includes a fully client-side Typst PDF report.
- Web sign-in validates the submitted username/password with Kerberos, permits only users whose winbind group SID set contains `DOMAIN_ADMINS_SID`, and issues an expiring JWT in a Secure, HttpOnly, SameSite=Strict cookie. The browser does not use NTLM/SPNEGO or Kerberos negotiation.
- HTTPS certificates are requested from a configured local Smallstep CA and renewed automatically. Pre-issued certificate files are also supported.
- Optional remote backups run when `BACKUP_DESTINATION` and `BACKUP_ARCHIVE_PASSWORD` are configured; each active or archived group folder is uploaded as its own encrypted, non-solid 7z archive.
- Private home creation skips well-known/service accounts by default (including `krbtgt`, `msol_*`, `FileShare_ServiceAcc`).
- Reconciliation is executed:
  - once on startup
  - every 5 minutes via cron
- Backup is executed:
  - manually through the Domain Admin web UI or CLI
  - daily at `BACKUP_START_HOUR` in UTC when `BACKUP_AUTO_ENABLED=true` (default: `true`; the switch is environment-only)

## Data Folder Lifecycle

The reconciliation script (`/app/reconcile_shares.py`) enforces these rules:

1. New matching `FS_*` group -> insert DB row and create `/data/groups/data/<groupName>`.
2. Group rename while still matching `FS_*` -> rename/update folder path.
3. Group removed or no longer matching `FS_*` -> set `isActive=0` and move folder to `/data/groups/archive/...`.
4. Previously inactive group returns -> set `isActive=1`, move back into `/data/groups/data/...`.

## Shared SQLite State Database

The default database path is `/state/shares.db`; `STATE_DB_PATH` can override it. `SHARE_DB_PATH` remains a backward-compatible fallback.

The database contains:

- `shares`: AD group-to-folder lifecycle and ACL reconciliation state;
- `audit_events`: normalized read, write, move, and delete events;
- `audit_sources`: Samba log inode/offset checkpoints;
- `web_cache`: cached storage scan results.

Activity lookup uses UTC epoch seconds, keyset pagination, and multi-column indexes for time, user, share, action, and result. WAL mode allows the collector, reconciler, scanner, and read-only web requests to operate concurrently.

Standard SQLite does not provide transparent general-purpose compression, so this project deliberately does not depend on a non-core compression VFS. Structured columns avoid repeated JSON field names and make indexed queries much cheaper; the state volume still needs capacity for retained activity.

## AD Requirements

- Existing AD DS domain reachable from the Docker host.
- Initial admin credentials with rights to create/reset `FileShare_ServiceAccount` during `./setup`.
- `FileShare_ServiceAccount` must be allowed to join computers to the domain (`net ads join`) in your AD policy.
- Dynamic group discovery primarily uses machine-account LDAP (`net ads search -P`); join credentials are only used as a fallback LDAP bind path.
- Group naming convention for Data folder eligibility:
  - `FS_<Anything>`
- Folder names use AD group display names (`displayName`, then `name`/`cn` fallback), not pre-2000 (`sAMAccountName`) names.

## DNS Requirements

- Container must resolve AD DNS records (especially SRV records for domain controllers).
- `DOMAIN` should resolve from inside the container.
- Preferred setup: Docker host uses AD-integrated DNS or forwards to AD DNS.
- If Docker bridge networking is used, set `AD_DNS_IP` to the Docker host LAN IP that clients should use for SMB, not the container `172.x` address.
- When `AD_DNS_IP` is set, domain join uses `--no-dns-updates`; each container startup unregisters/re-registers `AD_DNS_NAME -> AD_DNS_IP` in AD DNS using the machine account.
- `./setup` and `./redeploy` auto-refresh `AD_DNS_IP` from the host route when `AD_DNS_IP_AUTO=1`.

## Time Sync Requirements

Kerberos requires close time alignment.

- Docker host clock must be synchronized (NTP/chrony/systemd-timesyncd).
- AD domain controllers must also be time-synchronized.
- If join/authentication fails unexpectedly, check time skew first.

## Repository Layout

- `Dockerfile`
- `docker-compose.yml`
- `setup`
- `.env.example`
- `README.md`
- `app/init.sh`
- `app/reconcile_shares.py`
- `app/backup_to_destination.py`
- `app/audit_collector.py`
- `app/audit_store.py`
- `app/state_db.py`
- `app/web_ui.py`
- `app/web/`
- `etc/samba/smb.conf`
- `dev/` (disposable AD DC, backup target, SMB client, seed data, and E2E assertions)
- `scripts/dev`
- `scripts/test-e2e`

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

The preview starts with group, Private, and FSLogix data. The client keeps current activity moving, while a real backup runs immediately and repeats in the background. Open the URL and use the credentials printed by the launcher. Defaults are:

```text
URL:      https://files.localhost:8443
Username: DEV\previewadmin
Password: PreviewAdmin123!
```

The generated CA is intentionally disposable. `scripts/dev` prints the temporary root certificate path so it can be trusted only for the duration of that run. Ctrl-C stops and removes all run-scoped containers, volumes, the network, and the temporary root. A watchdog performs the same cleanup if the parent script is killed.

The dummy DC alone receives `SYS_ADMIN`, which Samba needs to write Windows ACL xattrs while provisioning `SYSVOL`; the application container receives no extra capability.

Useful overrides:

| Variable | Default | Purpose |
| --- | --- | --- |
| `DEV_HTTPS_PORT` | `8443` | HTTPS port bound to host loopback |
| `DEV_WEB_HOSTNAME` | `files.localhost` | HTTPS name validated by the disposable ACME CA |
| `DEV_SKIP_BUILD` | `0` | Set to `1` to reuse already-built local images |
| `DEV_CA_IMAGE` | `docker.io/smallstep/step-ca:latest` | CA image; pin a tag or digest for reproducible CI |
| `DEV_SERVER_IMAGE` | `ad-ds-simple-file-server-dev:latest` | Local file-server image name |
| `DEV_AD_IMAGE` | `ad-ds-simple-file-server-ad-dev:latest` | Local AD/client image name |
| `DEV_BACKUP_IMAGE` | `ad-ds-simple-file-server-backup-dev:latest` | Local rsync target image name |
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
- domain trust, group-to-folder mapping, nested and transitive group trees;
- SMB allow/deny behavior and real file operations;
- Data, Private, and FSLogix usage aggregation;
- high-level `full_audit` ingestion for all four actions, service-account exclusion, filters, facets, and pagination;
- shared SQLite schema, integrity, indexes, legacy-log removal, and ordered read deduplication;
- real rsync transfer progress, completed backup status, log output, remote snapshot marker, and per-group encrypted non-solid 7z archives;
- anonymous action rejection plus authenticated manual backup and reconciliation actions, terminal progress, and live reconciliation output;
- overview and system-health aggregation;
- the log-free PDF report snapshot plus local Typst wrapper, WebAssembly, font MIME types, and immutable caching.

The runner returns non-zero on the first failed assertion, prints bounded logs from every run-scoped service, and always removes its containers, volumes, network, and temporary CA root. Set `DEV_SKIP_BUILD=1` for a fast rerun against existing local images.

## Setup

1. Run interactive setup:

   ```bash
   ./setup
   ```

2. If `.env` is missing, you will be prompted for:
   - `REALM`
   - `WORKGROUP`
   - `DOMAIN`
   - `AD_DNS_IP` (host LAN IP to publish in AD DNS)
   - optional `AD_DNS_NAME` (defaults to `SAMBA_HOSTNAME.DOMAIN`)
   - initial admin credentials (used once for provisioning)
   - `DOMAIN_USERS_SID`
   - `DOMAIN_ADMINS_SID`
   - optional `FSLOGIX_GROUP_SID` (defaults to `DOMAIN_USERS_SID`)
   - optional `BACKUP_DESTINATION` (empty disables backup)
   - `BACKUP_ARCHIVE_PASSWORD` when a backup destination is configured
   - optional environment-only `BACKUP_AUTO_ENABLED` (`true` or `false`, default `true`)
   - optional `BACKUP_START_HOUR` (0-23, default `2`; used only when automatic backups are enabled)
   - optional `BACKUP_RETENTION_DAILY` (default `3`)
   - optional `BACKUP_RETENTION_WEEKLY` (default `2`)
   - optional `BACKUP_RETENTION_MONTHLY` (default `2`)
   - optional `BACKUP_RETENTION_YEARLY` (default `1`)
   - optional `BACKUP_LOG_FILE` (default `/var/log/backup.log`)
   - optional `BACKUP_PROGRESS` (`auto`, `always`, or `never`; default `auto`)
   - optional `BACKUP_PROGRESS_INTERVAL_SECONDS` (default `10`)
   - `WEB_HOSTNAME` (the DNS name in the HTTPS certificate)
   - optional `WEB_HTTPS_PORT` (host port, default `443`)
   - `ACME_CA_SERVER` (ACME directory URL)
   - either an ACME CA root bundle on the host or an `ACME_CA_CERTIFICATES_URL` for one-time retrieval
   - optional `ACME_HTTP_PORT` (HTTP-01 host port, default `80`)

   Setup generates a random `WEB_JWT_SECRET` and either imports the selected public CA root or configures its one-time download to `/state/tls/acme-ca-certificates.pem`.

   Optional:
   - `SAMBA_HOSTNAME` (defaults to `adsambafsrv`)
   - `NETBIOS_NAME` (defaults to `ADSAMBAFSRV`, max 15 chars)

3. Setup behavior:
   - creates or updates AD service account from desired name `FileShare_ServiceAccount`
   - uses a valid AD `sAMAccountName` (max 20 chars); default effective value is `FileShare_ServiceAcc`
   - always sets a long random password
   - writes only service-account credentials to `.env` (initial admin credentials are not stored)
   - writes `AD_DNS_IP` so container restarts keep AD DNS pointed at the host LAN IP

4. The setup script then starts the service with:

   ```bash
   docker compose up -d
   ```

5. After startup:
    - container joins AD (idempotent)
    - startup reconciliation runs
    - cron runs reconciliation every 5 minutes

## SMB Shares

### Private

- Share: `\\server\Private`
- Root path: `/data/private`
- Per-user path: `/data/private/<samAccountName>`
- Script ensures user directories exist and assigns ownership through winbind identity resolution.
- Root `/data/private` is enforced read/execute-only (`0555`) to prevent folder creation directly under `\\server\Private`.
- SMB-side ACL changes on `\\server\Private` are blocked (`nt acl support = no`).
- Auto-creation skips well-known/service/non-login accounts (disabled, locked, or expired).
- Each private user tree is reconciled recursively to homogeneous permissions (dirs `0700`, files `0600`, user/admin ACLs).
- Permissions:
  - owner user: full control
  - Domain Admins: ACL full control
  - mode: `700`
- `hide unreadable = yes` + ACLs enforce that users only see their own folder.

### Data

- Share: `\\server\Data`
- Path: `/data/groups/data`
- Contains one folder per active `FS_*` AD group.
- Root is discoverable as one share, while access to each group folder is enforced via POSIX/ACL group permissions.
- `FS_*` groups may contain other AD groups; reconciliation recursively grants ACLs to nested groups and logs detected cycles.
- Samba blocks SMB-side ACL edits on Data and forces new items to inherit the group folder owner, group, mode, and default ACLs.
- Normal reconciliation refreshes each group folder root; recursive subtree repair runs only when the resolved ACL signature changes, is missing, or `REPAIR_DATA_ACLS=1` is set.
- Dot-prefixed group folder names are allowed and are not hidden over SMB.
- No guest access.

### FSLogix

- Share: `\\server\FSLogix`
- Path: `/data/fslogix`
- Access for authenticated users in configurable `FSLOGIX_GROUP_SID` (default: `DOMAIN_USERS_SID`, resolved through winbind).
- Semantics intentionally differ from `Data`: only the share root is reconciled (`03770` + ACL defaults), while user-created profile container folders/files are not recursively normalized.
- Samba masks are profile-container oriented (`create mask = 0600`, `directory mask = 0700`) so profile payload stays user-private by default.

## Web Administration Console

Open `https://<WEB_HOSTNAME>/` after setup. Only members of the group identified by `DOMAIN_ADMINS_SID` can sign in. The form accepts `DOMAIN\username`, `username@realm`, or an unqualified username (which is qualified with `WORKGROUP`).

The console is intentionally operational and plain:

- **Overview**: current capacity totals, active group count, recent activity, and backup state.
- **File shares**: one selectable tree per active `FS_*` group/folder with recursively expanded user, nested-group, and AD primary-group membership, cycle markers, and a live filter.
- **Data usage**: cached recursive size of every top-level `/Data` group folder.
- **User usage**: per-user `/Private + /FSLogix` totals with component sizes.
- **Activity**: dynamic date, user, share, action, result, and path filters with pagination.
- **Share reconciliation**: manually force reconciliation and follow its phase, progress bar, current group, and live output.
- **Backups**: manually start a backup and follow live progress, active transfer rows, snapshot name, trigger, and recent output.
- **PDF report**: storage totals and every storage row, complete group/folder membership hierarchies, current backup state, system checks, and TLS certificate data.
- **System**: domain trust, Samba configuration, TLS certificate, scanner, and activity database health.

The PDF report deliberately excludes the activity log and backup log. Its dedicated snapshot endpoint removes those fields before returning data. Typst, its WebAssembly compiler, and the report fonts are shipped with the application; Typst source and PDF bytes are created only in the authenticated browser and are never uploaded to another service. The first export downloads roughly 22 MiB of compiler/font assets, which are then cached as immutable files. The CSP grants only `'wasm-unsafe-eval'` for WebAssembly compilation and does not enable JavaScript `'unsafe-eval'`.

The only operational mutation endpoints start an immediate backup or share reconciliation, and both require the same Domain Admin JWT as every protected page. The console cannot edit files, groups, ACL rules, backup schedules, retention, or `BACKUP_AUTO_ENABLED`. Automatic backups can be enabled or disabled only through the environment and therefore require a redeployment/restart.

### Authentication and sessions

- Credentials are submitted only over HTTPS. The password is passed to `kinit` through stdin, is never placed in a process argument, and the temporary Kerberos credential cache is immediately removed.
- After Kerberos succeeds, the service resolves the account SID and its complete group SID set through winbind. Login succeeds only when that set contains `DOMAIN_ADMINS_SID`.
- Authentication is form-based; the browser never performs NTLM, SPNEGO, or Kerberos negotiation.
- JWTs use HMAC-SHA256, default to eight hours, and are accepted from the protected cookie or an `Authorization: Bearer` header.
- Login attempts are rate-limited per client address.
- Responses set HSTS, a restrictive Content Security Policy, clickjacking protection, and MIME sniffing protection. APIs and ordinary UI assets use no-store caching; pinned Typst compiler/font assets use immutable long-term caching.

### TLS with an internal ACME CA

The default uses standard ACME HTTP-01 enrollment. The names deliberately describe the protocol and inputs rather than a particular CA product:

```env
WEB_ENABLED=true
WEB_HOSTNAME=files.example.com
WEB_HTTPS_PORT=443
WEB_JWT_SECRET=<at-least-32-random-bytes>
WEB_TLS_MODE=acme
ACME_CA_SERVER=https://ca.internal/acme/acme/directory
ACME_CA_CERTIFICATES=/state/tls/acme-ca-certificates.pem
ACME_CA_CERTIFICATES_URL=https://ca.internal/roots.pem
ACME_CA_CERTIFICATES_INSECURE_DOWNLOAD=true
ACME_HTTP_LISTEN=:80
ACME_HTTP_PORT=80
```

`ACME_CA_CERTIFICATES` is the persistent destination inside the file-server container. If that path does not exist and `ACME_CA_CERTIFICATES_URL` is set, the service downloads at most 4 MiB over HTTPS, validates that the result contains readable certificate data, and atomically installs it. Once the destination exists, it is never downloaded or overwritten again—not even when it is empty or invalid. Removing the file is therefore an explicit operator action that permits a new bootstrap download.

HTTPS verification is enabled by default. `ACME_CA_CERTIFICATES_INSECURE_DOWNLOAD=true` explicitly enables a one-time trust-on-first-use bootstrap equivalent to `curl -k`; it is useful when the server certificate is signed by the very root being fetched. This protects subsequent starts but cannot protect the first download from a man-in-the-middle attack, so compare the downloaded root fingerprint through an independent channel when possible. Instead of downloading, setup can import a local PEM bundle into the same destination.

The CA must be able to resolve `WEB_HOSTNAME` and reach `http://WEB_HOSTNAME/.well-known/acme-challenge/...` on port 80. `ACME_HTTP_LISTEN` controls the in-container standalone challenge listener and `ACME_HTTP_PORT` controls the Compose host-port mapping.

The equivalent Traefik settings translate as follows:

| Traefik setting | File-server setting |
| --- | --- |
| `acme.httpchallenge=true` | `WEB_TLS_MODE=acme` |
| `acme.httpchallenge.entrypoint=http` | `ACME_HTTP_LISTEN=:80` and `ACME_HTTP_PORT=80` |
| `acme.caserver=https://ca.internal/acme/acme/directory` | `ACME_CA_SERVER=https://ca.internal/acme/acme/directory` |
| `acme.cacertificates=/traefik/stepca/roots.pem` | `ACME_CA_CERTIFICATES=<persistent PEM destination inside this container>` |
| one-time equivalent of `curl https://ca.internal/roots.pem -k` | `ACME_CA_CERTIFICATES_URL=https://ca.internal/roots.pem` and `ACME_CA_CERTIFICATES_INSECURE_DOWNLOAD=true` |

The client uses [`step ca certificate --acme --root --standalone`](https://smallstep.com/docs/step-cli/reference/ca/certificate/) and periodically checks whether the certificate needs renewal. Renewal is a fresh ACME order, so this mode is not coupled to a proprietary renewal endpoint. The HTTPS listener reloads the replaced certificate files.

A generic direct-CA/JWK or token enrollment mode remains available when ACME HTTP-01 cannot be routed:

```env
WEB_TLS_MODE=ca
TLS_CA_URL=https://ca.internal:9000
TLS_CA_FINGERPRINT=<root-certificate-fingerprint>
TLS_CA_PROVISIONER=fileserver
TLS_CA_PROVISIONER_PASSWORD=<provisioner-password>
# TLS_CA_PROVISIONER_PASSWORD_FILE=/run/secrets/ca-provisioner-password
# TLS_CA_TOKEN=<single-use-bootstrap-token>
# TLS_CA_REBOOTSTRAP=false
# TLS_CA_STATE_DIR=/state/tls-client
```

Externally managed certificate files can be used instead:

```env
WEB_TLS_MODE=files
WEB_TLS_CERT_FILE=/state/tls/web.crt
WEB_TLS_KEY_FILE=/state/tls/web.key
```

Useful optional settings:

| Variable | Default | Purpose |
| --- | ---: | --- |
| `ACME_CA_CERTIFICATES_URL` | unset | HTTPS URL used only when the persistent root bundle does not exist |
| `ACME_CA_CERTIFICATES_INSECURE_DOWNLOAD` | `false` | Disable TLS verification only for that initial root download |
| `WEB_TLS_AUTORENEW` | `true` | Renew managed certificates automatically |
| `ACME_RENEW_CHECK_SECONDS` | `900` | Interval for ACME renewal checks; minimum 60 seconds |
| `WEB_JWT_TTL_SECONDS` | `28800` | Session lifetime, 5 minutes to 7 days |
| `WEB_LOGIN_ATTEMPTS_PER_5_MIN` | `10` | Per-address login attempt limit |
| `WEB_USAGE_SCAN_INTERVAL_SECONDS` | `900` | Recursive storage scan interval |
| `WEB_DIRECTORY_CACHE_SECONDS` | `300` | AD membership tree cache time |
| `WEB_MAX_GROUP_NODES` | `10000` | Membership expansion safety limit |
| `STATE_DB_PATH` | `/state/shares.db` | Shared SQLite database for shares, activity, collector offsets, and caches |
| `AUDIT_QUERY_MAX_DAYS` | `31` | Largest activity query window |
| `AUDIT_SKIP_USER_SUFFIXES` | `_svc,_ServiceAcc` | Case-insensitive account suffixes excluded from collection and queries; set empty to disable |

If `WEB_ENABLED` is absent on an upgraded installation and no TLS settings/certificate exist, the web service stays disabled while Samba and audit collection continue. Set `WEB_ENABLED=true` after adding TLS configuration.

## Activity Database

Samba emits only the selected high-level `full_audit` operations, and the collector stores them durably:

- it tails every `/var/log/samba/log.*` source and stores inode/byte offsets transactionally in `audit_sources`, so source progress and inserted events commit together;
- each event records a UTC timestamp, user, client address/name, share, result, path, and one of `read`, `write`, `move`, or `delete`;
- directory listings, sessions, metadata access, file-open/create noise, and all other VFS operations are discarded; users ending in a configured `AUDIT_SKIP_USER_SUFFIXES` value are also discarded;
- immediately consecutive identical reads within the same UTC second are collapsed into one event, including across collector polling cycles; a different event interrupts the sequence and preserves later reads;
- activity queries run directly against indexed SQLite columns and use a stable time/id cursor;
- no activity retention deletion is performed.

Collection starts even when the web UI is disabled. On the first collector start after this migration, recognized legacy daily `.jsonl`/`.jsonl.gz` files and the old collector state file under `/state/audit` are deleted without import. Existing raw Samba log content is then processed using the current action, suffix, and deduplication policy.


## Backups

- Backups are available only if `BACKUP_DESTINATION` is non-empty and `BACKUP_ARCHIVE_PASSWORD` is set.
- Each run creates a timestamped snapshot under `snapshots/YYYYMMDDTHHMMSSZ` at the destination.
- `BACKUP_AUTO_ENABLED=true` schedules the job daily at `BACKUP_START_HOUR` in UTC. With `false`, no backup cron entry is installed; manual web and CLI runs remain available. This setting is environment-only and cannot be changed through the web API.
- The container and Compose service force `TZ=Etc/UTC`.
- Sources synced to destination on each run:
  - `/data/private` -> `data/private`
  - `/data/groups` -> `data/groups`; direct group directories below `data` and `archive` become one `<group>.7z` each
  - `/data/fslogix` -> `data/fslogix`
  - `/state` -> `state` (the live WAL database is replaced by a consistent SQLite online snapshot)
  - `/var/lib/samba/private` -> `samba/private`
- Retention policy env vars (defaults):
  - `BACKUP_RETENTION_YEARLY=1`
  - `BACKUP_RETENTION_MONTHLY=2`
  - `BACKUP_RETENTION_WEEKLY=2`
  - `BACKUP_RETENTION_DAILY=3`
- The backup script writes directly to `BACKUP_LOG_FILE` (default: `/var/log/backup.log`). Cron does not redirect backup output into the logfile.
- Before uploading, the backup script creates a temporary, integrity-checked SQLite online snapshot of the shared state database.
- Each direct active and archived group folder is then compressed with LZMA2 at level 5 and multithreading into one non-solid (`-ms=off`) 7z archive. Header/data encryption is enabled (`-mhe=on`); the password comes only from `BACKUP_ARCHIVE_PASSWORD` and is supplied to 7z through stdin, never as a process argument. Non-group entries below `/data/groups` are preserved unchanged.
- `BACKUP_ARCHIVE_TEMP_DIR` selects the local staging directory (default `/tmp`). It must have enough free space for the compressed group archives. Staging data is removed after success or failure.
- Losing `BACKUP_ARCHIVE_PASSWORD` makes the group archives unrecoverable; keep it in the same secret-management system as the remote-backup credentials.
- After staging, the script measures all upload sources so it can report total transfer progress.
- Upload progress is logged per file every `BACKUP_PROGRESS_INTERVAL_SECONDS` seconds and again when a file reaches 100%, including percentage and transferred/remaining bytes with auto-scaled units.
- `BACKUP_PROGRESS=auto` shows an interactive multi-line progress view only for TTY/manual runs. Current file uploads are shown as separate rows, capped at 12 rows, with the total progress row at the bottom. Use `always` to force it or `never` to suppress the bar. File and total progress are still logged.
- Every run atomically updates `BACKUP_STATUS_FILE` (default `/state/backup-status.json`) with its state, current source, active files, byte totals, percentage, snapshot, and final result for the live web view.
- Rclone-backed destinations cap concurrent file transfers at 12. Rsync remains single-streamed by rsync itself.
- Retention logic:
  - daily: newest N snapshots
  - weekly: newest N snapshots created on week start (Monday)
  - monthly: newest N snapshots created on day 1
  - yearly: newest N snapshots created on Jan 1
  - snapshots selected by any tier are retained; all others are pruned
- Supported destination schemes:
  - `rsync://user:pass@host/module/path`
  - `smb://user:pass@host/share/path` (domain user example: `smb://DOMAIN%5Cuser:pass@host/share/path`)
  - `davfs://user:pass@host/path` (WebDAV over HTTPS)
  - `sftp://user:pass@host/path`
- Username/password components should be URL-encoded when they contain reserved characters (`@`, `:`, `/`, `\`, `%`, `#`, `?`).

- Example:

  ```env
  BACKUP_DESTINATION=sftp://backupuser:StrongPassword@sftp.example.com/exports/samba
  BACKUP_ARCHIVE_PASSWORD=use-a-long-random-secret
  BACKUP_AUTO_ENABLED=true
  BACKUP_START_HOUR=2
  BACKUP_ARCHIVE_TEMP_DIR=/tmp
  BACKUP_RETENTION_DAILY=3
  BACKUP_RETENTION_WEEKLY=2
  BACKUP_RETENTION_MONTHLY=2
  BACKUP_RETENTION_YEARLY=1
  BACKUP_LOG_FILE=/var/log/backup.log
  BACKUP_PROGRESS=auto
  BACKUP_PROGRESS_INTERVAL_SECONDS=10
  ```

## Useful Commands

```bash
docker compose logs -f samba
docker compose logs -f samba | grep -E '\\[web\\]|\\[audit\\]'
docker compose exec samba python3 /app/reconcile_shares.py
docker compose exec samba python3 /app/backup_to_destination.py
docker compose exec samba sqlite3 /state/shares.db 'PRAGMA quick_check;'
docker compose exec samba sqlite3 /state/shares.db 'SELECT action, count(*) FROM audit_events GROUP BY action;'
docker compose exec samba testparm -s
docker compose exec samba sh -lc 'tail -n 200 /var/log/samba/log.*'
docker compose exec samba sh -lc 'tail -n 200 /var/log/backup.log'
docker compose exec samba python3 -m json.tool /state/backup-status.json
docker compose exec samba python3 -m json.tool /state/reconcile-status.json
```

## Troubleshooting

### Domain join fails

- Verify service account credentials in `.env`.
- Verify DNS resolution from container:

  ```bash
  docker compose exec samba getent hosts "$DOMAIN"
  ```

- Verify time sync on host and AD DCs.
- Verify NetBIOS name length is <= 15:

  ```bash
  docker compose exec samba testparm -s | grep -i 'netbios name'
  ```

### AD DNS points at 172.x

- This means Samba registered the container bridge IP.
- Ensure `.env` contains `AD_DNS_IP=<host LAN IP>` and `AD_DNS_NAME=<server FQDN>`.
- Recreate/restart the container so startup re-registers AD DNS:

  ```bash
  docker compose up -d --force-recreate samba
  ```

### Winbind user/group resolution fails

- Check trust:

  ```bash
  docker compose exec samba wbinfo -t
  ```

- List users/groups:

  ```bash
  docker compose exec samba wbinfo -u
  docker compose exec samba wbinfo -g
  ```

### Data folders not appearing

- Confirm AD groups match `FS_*`.
- Run manual reconciliation and inspect logs:

  ```bash
  docker compose exec samba python3 /app/reconcile_shares.py
  docker compose exec samba tail -n 100 /var/log/reconcile.log
  ```

### Nested or primary Data group access fails

- Check reconciliation logs for detected group cycles or unresolved nested members.
- The reconciler resolves group SIDs to GIDs first, so localized names such as `Domänen-Benutzer` do not affect ACL generation.
- Verify the SID mapping, the user's primary/supplementary groups, and the resulting ACL:

  ```bash
  docker compose exec samba wbinfo --name-to-sid 'EXAMPLE\Domänen-Benutzer'
  docker compose exec samba wbinfo --sid-to-gid S-1-5-21-...-513
  docker compose exec samba id 'EXAMPLE\alice'
  docker compose exec samba getfacl /data/groups/data/<groupName>
  ```

Users whose group is represented only by AD `primaryGroupID` are included automatically; they do not need to appear in the group's LDAP `member` attribute.

### Data folder permissions are incorrect

- Normal reconciliation avoids walking every file when the resolved ACL signature is unchanged.
- Force a recursive repair for all active Data group folders with:

  ```bash
  docker compose exec samba sh -lc 'REPAIR_DATA_ACLS=1 python3 /app/reconcile_shares.py'
  ```

- After a successful repair, later cron runs return to root-only Data ACL refreshes unless group ACLs change again.

### `acl_xattr.so` or `full_audit.so` module load error

- If logs show `Error loading module .../vfs/acl_xattr.so` (or `full_audit.so`), your running image is missing Samba VFS modules.
- Rebuild and restart with the updated image:

  ```bash
  docker compose down
  docker compose up -d --build
  ```

- Verify modules exist:

  ```bash
  docker compose exec samba sh -lc 'mods="$(smbd -b | sed -n "s/^ *MODULESDIR: //p" | head -n1)/vfs"; ls -1 "$mods"/acl_xattr.so "$mods"/full_audit.so'
  ```

### Permissions in Private share are incorrect

- Re-run reconciliation to rebuild private directories and ACLs:

  ```bash
  docker compose exec samba python3 /app/reconcile_shares.py
  ```

- Check identity resolution for a user:

  ```bash
  docker compose exec samba id 'EXAMPLE\\alice'
  ```

## Notes

- User data is never automatically deleted.
- Inactive/deleted FS_* groups are moved to `/data/groups/archive`.
- Data and state survive container restarts via named Docker volumes (`/data/*`, `/state`, `/var/lib/samba`).
