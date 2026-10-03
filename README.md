# AD-Integrated Containerized Samba File Server

This repository provides a production-oriented Samba file server container that joins an existing Active Directory domain and exposes three SMB shares: `Private`, `Data`, and `FSLogix`.

## Architecture

- Samba runs in ADS mode with `winbind` identity mapping.
- Static shares:
  - `\\server\Private` -> `/data/private`
  - `\\server\Data` -> `/data/groups/data`
  - `\\server\FSLogix` -> `/data/fslogix`
- Data folders and individual user permissions are managed in the admin web UI. AD remains the source of user identities and authentication.
- Data access uses Windows ACLs stored in Samba’s protected `/state/data-xattrs.tdb`, with separate read, modify, and delete permissions.
- Folder and permission records, normalized activity events, collector offsets, and web caches share one SQLite database at `/state/shares.db`.
- Managed folders are name-based while active and moved to archive through the admin UI:
  - active: `/data/groups/data/<folderName>`
  - archived folders: `/data/groups/archive/<folderName>`
- Samba machine trust/key material is persisted in `/var/lib/samba` to survive container recreation.
- Container hostname is fixed (`SAMBA_HOSTNAME`) to keep AD computer identity stable.
- In bridge-mode Docker networking, startup can publish the host LAN IP in AD DNS with `AD_DNS_IP`/`AD_DNS_NAME` instead of the container bridge IP.
- NetBIOS name defaults to `ADSAMBAFSRV` and is clamped to 15 characters (`NETBIOS_NAME` override supported).
- Setup prompts for well-known authorization groups by SID (`DOMAIN_USERS_SID`, `DOMAIN_ADMINS_SID`) to avoid localized group names.
- `FSLOGIX_GROUP_SID` controls who can access the default FSLogix share (defaults to `DOMAIN_USERS_SID`).
- Startup resolves those SIDs to NSS group names via winbind, then uses those resolved groups in Samba `valid users` rules.
- Samba `full_audit` records successful and failed reads, writes, renames, and deletions on all three shares; FSLogix events are retained in a separate indexed activity stream.
- A collector normalizes those four actions and persists them in indexed SQLite tables; activity is never automatically deleted.
- Samba retains deleted files for seven days in per-user recycle repositories on the same data volumes.
- The HTTPS file interface at `/` lets AD users search accessible Data folders and their own Private folder. An independent background worker indexes text and recognizes scanned PDFs without changing original files.
- The administration console at `/admin/...` manages Data folders and individual user access, and provides statistics, logs, trash downloads/restores, manual backups, and share reconciliation. It also includes a fully client-side Typst PDF report.
- Web sign-in validates the submitted username/password with Kerberos and issues an expiring JWT in a Secure, HttpOnly, SameSite=Strict cookie. Human AD users can sign in; `MSOL_*` and `krbtgt` accounts are excluded. Administration pages and APIs require membership in `DOMAIN_ADMINS_SID`. The browser does not use NTLM/SPNEGO or Kerberos negotiation.
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

The **Zugriffsverwaltung** page creates top-level Data folders, assigns a permission level to each existing AD user individually per folder. It can archive folders and restore them without deleting their contents. AD accounts and passwords continue to be administered in AD.

| Level | Access |
| --- | --- |
| 0 | No access; folder hidden |
| 1 | Read only |
| 2 | Read, create, and edit; no delete |
| 3 | Read, create, edit, and delete |

No assignment means no access. Each user has an independent level per folder; level 0 revokes access. There are no access groups. Domain Admins retain full access. Only admins can rename or delete a top-level managed folder.

Level 2 blocks renaming and moving files or directories because SMB requires delete permission for those operations. Applications that save by deleting/replacing a file or renaming a temporary file require level 3. Level 2 still permits overwriting a file’s contents in place.

Saving applies ACL changes recursively when the effective policy changes and disconnects existing Data connections so clients reopen with the new permissions. Changes record the administrator, timestamp, action, and submitted policy in `access_changes`. The five-minute reconciler repairs folder roots and recovers interrupted access updates; `REPAIR_DATA_ACLS=1` forces a full repair.

### Upgrading from FS_* groups

On the first startup, existing active `shares` records are retained. Nested and primary-group memberships are expanded into a snapshot of individual user SIDs, each receiving level 3 on its existing folders. Folder identities and data are retained. An unresolved group or member stops migration with an error so an incomplete import cannot silently remove access.

Legacy GUID directories stored as `/data/groups/<objectGUID>` are moved into `/data/groups/data/<folderName>` (or `archive` for inactive records) before ACL reconciliation. Existing target directories are preserved; collisions receive a unique folder name. Moves use an atomic no-overwrite rename on the existing volume and retain file inodes and contents. A committed move journal recovers interruptions between filesystem and database updates. This layout repair also runs when the access migration was already marked complete, preserving saved individual permissions and avoiding another AD import. Missing or ambiguous paths stop recovery without creating empty replacements or deleting either path.

After import, AD group renames, membership changes, deletion, and new `FS_*` groups do not change Data folders or access. Manage subsequent changes in the web UI. User assignments are keyed by SID, so renaming an AD account retains its assignments; recreating an account under the same username does not inherit them.

Installations using the previous app-local group model are upgraded atomically to individual assignments. The highest prior group grant is retained per user and folder, with existing direct assignments taking precedence, including level 0. Archived folder assignments are preserved. Group tables and group mutation actions are removed.

A new installation starts without assignments. Existing untracked Data directories are adopted with admin-only access. Previously archived folders remain archived and need explicit permissions before users can access them after restoration.

The Data share uses Samba Windows ACL checks instead of POSIX ACLs. Keep its data volumes private to the container; direct local or NFS access is outside this permission model. The protected TDB store avoids requiring extra container capabilities. After restoring Data to different filesystem inodes, run reconciliation with `REPAIR_DATA_ACLS=1` to rebuild ACL records. Trash restoration applies the current folder policy before exposing the restored file.

## File Search and PDF Recognition

Users sign in at `/` with their existing AD credentials using `username`, `DOMAIN\username`, or `username@domain`. Domain-qualified names accept the configured AD DNS domain/realm; the short NetBIOS domain is also accepted after `@`. The file view provides live search by filename and content, folder and file-type filters, grid/list views, previews, and downloads of the original files. Grid and list entries show file metadata without extracted content snippets. Only Domain Admins see the administration link and can use management pages and APIs under `/admin/...`; old administration URLs redirect there. Administrative APIs are under `/admin/api/...`, while sign-in, session, and document endpoints remain under `/api/...`. This upgrade expires existing web sessions.

The catalog includes active Data folders and each user's own Private folder. Every search, detail, preview, and download request checks current individual folder permissions. Revoking access or archiving a folder takes effect without waiting for reindexing. Domain Admins can see all active Data folders, but the user file view still shows only their own Private folder. Archived folders, recycle repositories, FSLogix profiles, symlinks, nested mounts, and special files are excluded. `Thumbs.db` (case-insensitive) and Office lock files whose names start with `~$` are omitted from results, counts and file-type filters in both Data and Private folders. Upgrades remove their existing catalog entries without deleting original files. Private files additionally require ownership and read/traverse permissions for the signed-in user's mapped Unix identity.

Linux filesystem events update the filename catalog as files change, with periodic scans recovering missed events. Text extraction and OCR run through a persistent background queue; files become searchable by filename before content extraction finishes. Search updates while typing, and open views refresh every two seconds to show completed extraction. Full-text queries match word prefixes and ignore accents; filename-only queries also match substrings.

Content search indexes only PDFs, Word documents (`docx`, `odt`) and PowerPoint presentations (`pptx`, `odp`). All file types remain searchable by filename, including text, Markdown, spreadsheets and images. Existing extracted content from excluded types is removed from the derived search index on upgrade; original files and filename entries remain intact. PDFs and common images receive a first-page/image thumbnail. PDFs open in a fullscreen dialog with the locally bundled Mozilla PDF.js viewer, including page navigation, zoom, thumbnails and search within native PDF text. PDF loading and byte-range requests check current folder access. Legacy binary Office formats (`doc`, `ppt`) remain searchable by filename. Extracted text is limited to 2 MiB per file; encrypted, damaged, or oversized documents may have no searchable content.

Only PDF pages that themselves contain raster images and little extracted text are queued for local OCR using Poppler and Tesseract, with German and English enabled by default. Search OCR renders those pages at 300 DPI, capped at 3500 pixels on the longest side, instead of inheriting high DPI from embedded logos or rebuilding an OCR PDF. Each render and recognition step has a 30-second timeout. Photos can still require a recognition attempt to establish whether they contain text; text-free pages finish without adding search content. Native text remains searchable while OCR is pending. OCR text is used for search. No file type displays a separate extracted document-text panel in its dialog. The PDF viewer displays the original PDF. Downloads always return the original file. No OCR replacement or separate OCR PDF is published. Failed jobs retry with backoff, and pending work survives restarts.

Parsers run as an unprivileged service account on temporary copies, with filesystem/network restrictions and resource limits. This requires a Linux kernel with Landlock enabled (Linux 5.13 or newer) on x86-64 or ARM64. If isolation is unavailable, extraction fails closed while filename search remains available; the worker logs the reason. OCR needs no external service or additional container capabilities.

The derived index and previews live in `/state/documents` (`DOCUMENT_STATE_ROOT` override), separate from the managed-access database. The directory is accessible only to the service. Backups retain all original files and access records, and omit this rebuildable cache. Restoring a backup rebuilds the catalog automatically. Allow space for extracted text, previews, and temporary OCR work; the first indexing pass runs asynchronously.

Domain Admins monitor the worker at `/admin/documents`: current file and phase, completed/total files, text/OCR queues, retries, heartbeat, last catalog scan, and recent activity. Pause and resume controls stop both catalog updates and extraction. Pausing interrupts an active parser and its child processes, discards its temporary workspace, and keeps the original queue phase for resumption. Existing indexed files remain searchable subject to current access rules. The pause flag survives container restarts. Control events record the administrator in the document activity history; status and control APIs are restricted to administrators. This derived worker history and its pause flag are omitted with the document cache from backups.

| Variable | Default | Purpose |
| --- | --- | --- |
| `DOCUMENT_SCAN_SECONDS` | `30` | Recovery scan interval; filesystem events handle intervening changes |
| `DOCUMENT_OCR_LANGUAGE` | `deu+eng` | Installed Tesseract languages used for OCR |
| `DOCUMENT_OCR_TIMEOUT_SECONDS` | `600` | Maximum runtime for an OCR job |
| `DOCUMENT_OCR_DPI` | `300` | OCR render resolution (150–400 DPI), subject to the pixel cap |
| `DOCUMENT_OCR_MAX_DIMENSION` | `3500` | Maximum OCR image width/height (1500–5000 pixels); originals are unchanged |
| `DOCUMENT_OCR_PAGE_TIMEOUT_SECONDS` | `30` | Maximum runtime per page render or recognition step (5–120 seconds) |
| `DOCUMENT_MAX_FILE_MB` | `512` | Largest file copied for extraction; larger files use filename search |
| `DOCUMENT_MAX_PDF_PAGES` | `500` | Maximum PDF page count for extraction |

These settings are passed through the existing Compose environment file. Setting `WEB_ENABLED=false` also disables the document worker.

## Shared SQLite State Database

The default database path is `/state/shares.db`; `STATE_DB_PATH` can override it. `SHARE_DB_PATH` remains a backward-compatible fallback.

The database contains:

- `shares`: managed folder lifecycle and ACL reconciliation state;
- `access_users`, `folder_permissions`, `access_settings`, and `access_changes`: managed access rules, cached AD identities, migration state, and administrative change history;
- `audit_events`: normalized read, write, move, and delete events;
- `audit_sources`: Samba log inode/offset checkpoints;
- `audit_event_dedup`: bounded, persistent fingerprints for restart-safe main-read and FSLogix-event deduplication;
- `audit_daily_totals`, `audit_daily_counts`, and `audit_daily_facets`: compact materialized metadata for fast activity counts and filters;
- `audit_paths`, `audit_paths_fts`, and `audit_path_events`: deduplicated trigram path search with an incrementally maintained event mapping;
- `audit_rollup_state`: bounded legacy-event backfill progress;
- `web_cache`: cached storage scan results.

Activity pages use UTC epoch seconds, keyset pagination, and compact indexes for time, scalar filters, and selective substring path searches. Exact scalar-filter counts and facets read the daily rollups instead of scanning raw events. WAL mode allows the collector, reconciler, scanner, and read-only web requests to operate concurrently.

Standard SQLite does not provide transparent general-purpose compression, so this project deliberately does not depend on a non-core compression VFS. Structured columns avoid repeated JSON field names and make indexed queries much cheaper; the state volume still needs capacity for retained activity.

## AD Requirements

- Existing AD DS domain reachable from the Docker host.
- Initial admin credentials with rights to create/reset `FileShare_ServiceAccount` during `./setup`.
- `FileShare_ServiceAccount` must be allowed to join computers to the domain (`net ads join`) in your AD policy.
- Directory reads use machine-account LDAP (`net ads search -P`); join credentials are only used as a fallback LDAP bind path.
- Existing AD users are selectable by the administrator; no AD group naming convention is required for new Data folders.
- Machine-account LDAP reads provide the user list and the one-time legacy membership import.

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

Neither the dummy DC nor the application container receives extra capabilities.

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
- domain trust, one-time legacy folder/membership migration, and individual folder assignments;
- legacy GUID-path migration with file hash/inode checks, and real container restart after an already-completed access migration;
- individual user assignments, all four SMB access levels, hidden-folder behavior, inheritance, ACL-edit rejection, revocation, and archive/restore;
- SMB allow/deny behavior and real file operations;
- Data, Private, and FSLogix usage aggregation;
- high-level `full_audit` ingestion for all four actions, service-account exclusion, filters, facets, and pagination;
- shared SQLite schema, integrity, indexes, legacy-log removal, and main-read and FSLogix-event deduplication across interleaved events and collector polls;
- real Samba recycle handling plus authenticated trash listing, streamed download, and restore;
- real rsync transfer progress, completed backup status, log output, remote snapshot marker, and per-group encrypted non-solid 7z archives;
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
- Contains the active top-level folders created or imported into the admin UI.
- Windows ACLs enforce each user’s effective level, including separate delete rights.
- Samba’s `acl_xattr` and `xattr_tdb` modules retain the ACLs in a protected store. Local access to the underlying volumes must remain restricted.
- New files and directories inherit the managed ACL. Users cannot change ACLs or take ownership to grant themselves more access.
- Normal reconciliation refreshes each folder root; recursive repair runs when its effective permission signature changes, is missing, or `REPAIR_DATA_ACLS=1` is set.
- Dot-prefixed folder names are allowed and are not hidden over SMB.
- No guest access.

### FSLogix

- Share: `\\server\FSLogix`
- Path: `/data/fslogix`
- Access for authenticated users in configurable `FSLOGIX_GROUP_SID` (default: `DOMAIN_USERS_SID`, resolved through winbind).
- Semantics intentionally differ from `Data`: only the share root is reconciled (`03770` + ACL defaults), while user-created profile container folders/files are not recursively normalized.
- Samba masks are profile-container oriented (`create mask = 0600`, `directory mask = 0700`) so profile payload stays user-private by default.

## Seven-Day Trash

Deletes through the `Private`, `Data`, and `FSLogix` SMB shares are intercepted by Samba's recycle VFS and moved into `.trash/<user>` on the same source volume. Moving on the same filesystem avoids copying even large profile containers. The original directory tree is retained, repeated deletions receive versioned names, and the deletion time is stored as the recycled file's modification time.

The repository root is owned by root, vetoed from SMB access, and excluded from usage accounting and remote backup snapshots. Temporary `*.tmp` files and document lock files beginning with `~$` are deleted normally instead of being retained; cleanup also purges any such entries left by an older configuration. Every hour—and once during container startup—the cleanup job permanently removes entries older than seven days. `TRASH_RETENTION_DAYS` defaults to `7` and may be set from `1` to `365`.

Domain Admins can use **Papierkorb** in the web console to filter and list retained files, stream-download them, or restore them to their original path. Restore is a same-filesystem link/unlink operation, so it is fast for large files and preserves file metadata. It never overwrites an existing file; a conflict is reported and the retained copy remains in the bin.

## Web Administration Console

Open `https://<WEB_HOSTNAME>/` after setup. Only members of the group identified by `DOMAIN_ADMINS_SID` can sign in. The form accepts `DOMAIN\username`, `username@realm`, or an unqualified username (which is qualified with `WORKGROUP`).

The console is intentionally operational and plain:

- **Overview**: current capacity totals, active folder count, recent activity, and backup state.
- **Zugriffsverwaltung**: create/archive/restore Data folders and assign levels 0–3 to existing AD users individually per folder.
- **Data usage**: cached recursive size of every top-level `/Data` group folder.
- **User usage**: per-user `/Private + /FSLogix` totals with component sizes.
- **Activity**: dynamic date, user, share, action, result, and path filters with pagination.
- **Trash**: list seven-day recycle entries across all shares, download a retained file, or restore it without overwriting an existing path.
- **Share reconciliation**: manually force reconciliation and follow its phase, progress bar, current group, and live output.
- **Backups**: manually start a backup and follow live progress, active transfer rows, snapshot name, trigger, and recent output.
- **PDF report**: storage totals and every storage row, individual folder/user assignments, current backup state, system checks, and TLS certificate data.
- **System**: domain trust, Samba configuration, TLS certificate, scanner, and activity database health.

The PDF report deliberately excludes the activity log and backup log. Its dedicated snapshot endpoint removes those fields before returning data. Typst, its WebAssembly compiler, and the report fonts are shipped with the application; Typst source and PDF bytes are created only in the authenticated browser and are never uploaded to another service. The first export downloads roughly 22 MiB of compiler/font assets, which are then cached as immutable files. The CSP grants only `'wasm-unsafe-eval'` for WebAssembly compilation and does not enable JavaScript `'unsafe-eval'`.

The mutation endpoints manage Data access (`POST /api/access`), restore retained files, or start an immediate backup/share reconciliation; all require the same Domain Admin JWT as every protected page. Restore cannot overwrite a live file. Backup schedules, retention, and `BACKUP_AUTO_ENABLED` are configured through the environment. Automatic backups can be enabled or disabled only through the environment and therefore require a redeployment/restart.

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
| `TRASH_RETENTION_DAYS` | `7` | Recycled-file lifetime; cleanup accepts 1 to 365 days |
| `STATE_DB_PATH` | `/state/shares.db` | Shared SQLite database for shares, activity, collector offsets, and caches |
| `AUDIT_QUERY_MAX_DAYS` | `31` | Largest activity query window |
| `AUDIT_SKIP_USER_SUFFIXES` | `_svc,_ServiceAcc` | Case-insensitive account suffixes excluded from collection and queries; set empty to disable |

If `WEB_ENABLED` is absent on an upgraded installation and no TLS settings/certificate exist, the web service stays disabled while Samba and audit collection continue. Set `WEB_ENABLED=true` after adding TLS configuration.

## Activity Database

Samba emits selected high-level `full_audit` operations for Private, Data, and FSLogix, and the collector stores them durably:

- it tails every `/var/log/samba/log.*` source and stores inode/byte offsets transactionally in `audit_sources`, so source progress and inserted events commit together;
- each event records a UTC timestamp, user, client address/name, share, result, path, and one of `read`, `write`, `move`, or `delete`;
- directory listings, sessions, metadata access, file-open/create noise, and all other VFS operations are discarded; users ending in a configured `AUDIT_SKIP_USER_SUFFIXES` value are also discarded;
- FSLogix profile-container events are retained and queried through their own partial indexes, API route, and UI log instead of appearing in the main activity stream;
- identical main-stream reads and identical FSLogix events within the same UTC second are collapsed regardless of intervening events, log source, or collector polling cycle; Data/Private writes remain distinct, and the 48-hour fingerprint window can be tuned with `AUDIT_DEDUP_WINDOW_SECONDS`;
- activity pages read only `limit + 1` indexed rows and use a stable time/id cursor;
- exact counts for date, user, share, action, and result filters and all facet lists come from daily rollups;
- selective substring path searches use the deduplicated trigram index and skip an expensive exact count while more pages exist;
- while a legacy backfill is running, pages return immediately without raw-table count or facet scans and expose indexing progress;
- collector inserts and rollup updates are batched in one transaction;
- no activity retention deletion is performed.

Collection starts even when the web UI is disabled. Existing databases remain queryable while the collector backfills rollups, path IDs, path-event mappings, and recent main-read and FSLogix-event deduplication in bounded chunks after prioritizing each live append. On the first collector start after the legacy archive migration, recognized daily `.jsonl`/`.jsonl.gz` files and the old collector state file under `/state/audit` are deleted without import. Existing raw Samba log content is then processed using the current action, suffix, and deduplication policy.


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
- Active status is reconciled against the kernel-held `/state/backup.lock`; if a container restart or forced termination releases the lock while status still says `starting` or `running`, the web API atomically records the run as interrupted instead of reporting a phantom backup.
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

### Data folders or access missing

- Check **Zugriffsverwaltung**: the folder must be active, and the user must have an individual assignment.
- Level 0 revokes access. Changes to AD `FS_*` membership do not change imported individual assignments.
- Check the reconciliation status and logs if the one-time import or an ACL update fails:

  ```bash
  docker compose exec samba python3 /app/reconcile_shares.py
  docker compose exec samba tail -n 100 /var/log/reconcile.log
  ```

- Inspect Windows ACLs with `smbcacls //server/Data '<folder>' -U 'DOMAIN\admin'`; `getfacl` does not show the enforced Data permissions.

### Data folder permissions are incorrect

- Normal reconciliation avoids walking every file when the resolved ACL signature is unchanged.
- Force a recursive repair for all active Data group folders with:

  ```bash
  docker compose exec samba sh -lc 'REPAIR_DATA_ACLS=1 python3 /app/reconcile_shares.py'
  ```

- After a successful repair, later cron runs return to root-only Data ACL refreshes unless group ACLs change again.

### Startup fails with `Unsafe managed folder path: /data/groups/<GUID>`

This indicates a legacy GUID directory still referenced by an already-migrated database. Update the application code/image and restart using the existing volumes:

```bash
docker compose stop samba
docker compose build samba
docker compose up -d --no-deps samba
docker compose logs --tail=100 samba
```

Startup repairs stored legacy paths without reimporting AD membership. It logs `Migrated legacy folder without overwriting data` for each completed move. Keep `/state` and all data volumes; do not remove volumes or reset the `managed` migration marker. If recovery reports a missing source or conflicting source/destination, both data paths remain untouched for inspection.

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
- Folders archived in the admin UI are moved to `/data/groups/archive`; AD group deletion does not move folders.
- Data and state survive container restarts via named Docker volumes (`/data/*`, `/state`, `/var/lib/samba`).
