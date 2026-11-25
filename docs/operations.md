# Operating DomainShare

[Back to DomainShare](../README.md)

Deploy DomainShare, manage shares and backups, or troubleshoot an existing installation.

## AD Requirements

- Existing Active Directory domain reachable from the Docker host.
- An AD account with permission to join the server to the domain and read directory users/groups.
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
- Configure the host LAN address used for AD DNS registration in the web setup or server settings.

## Time Sync Requirements

Kerberos requires close time alignment.

- Docker host clock must be synchronized (NTP/chrony/systemd-timesyncd).
- AD domain controllers must also be time-synchronized.
- If join/authentication fails unexpectedly, check time skew first.

## Setup

No environment file is required. Run `./setup` to build and start the service, then open `http://<server>/`. HTTP exposes only HTTPS configuration: enter the separate HTTPS setup code from `docker compose logs samba`, choose the HTTPS hostname and ACME directory URL, and optionally upload a PEM root CA certificate. Public CAs use the system trust bundle. The ACME CA must resolve the hostname and reach its HTTP-01 challenge on port 80.

Once issuance succeeds, follow the HTTPS link. Enter the second, independent setup code from the container log. This code is used only over HTTPS. Configure the AD realm, NetBIOS domain, controller, domain-join/LDAP credentials and server names. After the domain join succeeds, select the AD groups for login, administration and FSLogix, and verify an account in the selected administrator group. Folder permissions remain individual assignments.

The web UI remains available if joining AD fails. Correct the settings and retry without removing any data volumes. The setup capability stops working after completion. Domain-join credentials are retained for LDAP; use an account with the necessary directory read and join permissions, or replace its credentials in administration after joining.

Administrators manage server settings at `/admin/settings` and backup destinations, schedules, retention and encryption at `/admin/backup`. Settings are stored in the root-only `/state/configuration.db`. Backup changes apply to the next run. Other changes restart the service processes, preserving files and the existing domain join; active SMB connections may reconnect. Switching to a different AD domain is deliberately rejected after setup.

For an existing installation, run `./setup` or `./redeploy`: the previous container’s resolved configuration is imported once when available; otherwise, its `.env` is imported without executing it. The original domain join, storage paths, access database, volumes, backup password, destinations and backup history are preserved. A configured installation ignores later `.env` edits. An unconfigured installation can also import its old file from the HTTPS setup screen. Keep the same Compose project name and volume names during the upgrade. Never use `docker compose down -v` on retained data.

The DomainShare rename changes the container and image names, not the Compose service (`samba`) or its volumes. If you move or rename an existing checkout, set `COMPOSE_PROJECT_NAME` to the previous Compose project name before running `./setup` or `./redeploy`, so Compose finds the existing volumes. Saved Samba DNS and NetBIOS names stay in place. Web users need to sign in again after the rename.

Compose publishes fixed ports 80 and 443, plus SMB 139 and 445. A deployment requiring different host ports can use a Compose override; it does not configure application credentials or backup destinations. TLS, AD settings and backup configuration are managed in the browser.

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

## Seven-Day Trash

Deletes through the `Private`, `Data`, and `FSLogix` SMB shares are intercepted by Samba's recycle VFS and moved into `.trash/<user>` on the same source volume. Moving on the same filesystem avoids copying even large profile containers. The original directory tree is retained, repeated deletions receive versioned names, and the deletion time is stored as the recycled file's modification time.

The repository root is owned by root, vetoed from SMB access, and excluded from usage accounting and remote backup snapshots. Temporary `*.tmp` files and document lock files beginning with `~$` are deleted normally instead of being retained; cleanup also purges any such entries left by an older configuration. Every hour—and once during container startup—the cleanup job permanently removes entries older than seven days. `TRASH_RETENTION_DAYS` defaults to `7` and may be set from `1` to `365`.

Domain Admins can use **Papierkorb** in the web console to filter and list retained files, stream-download them, or restore them to their original path. Restore is a same-filesystem link/unlink operation, so it is fast for large files and preserves file metadata. It never overwrites an existing file; a conflict is reported and the retained copy remains in the bin.

## Web Administration Console

Open `https://<WEB_HOSTNAME>/` after setup to search files. Domain Admins can open the administration console at `/admin/`; its APIs require membership in the group identified by `DOMAIN_ADMINS_SID`. The form accepts `DOMAIN\username`, `username@realm`, or an unqualified username (which is qualified with `WORKGROUP`).

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

The mutation endpoints under `/admin/api/` manage Data access, restore retained files, control indexing, or start an immediate backup/share reconciliation. They require an active Domain Admin session and CSRF protection. Restore cannot overwrite a live file. Backup schedules, destinations, retention and encryption are configured through `/admin/backup`, without redeploying.

### Authentication and sessions

- Credentials are submitted only over HTTPS. The password is passed to `kinit` through stdin, is never placed in a process argument, and the temporary Kerberos credential cache is immediately removed.
- After Kerberos succeeds, the service resolves the account SID, Unix UID and complete group SID set through winbind. Human AD users can sign in; only members of `DOMAIN_ADMINS_SID` receive administration access. Sessions recheck that identity through winbind on their first request after `WEB_AUTH_RECHECK_SECONDS` (default 60 seconds). Directory failures deny data and administration requests; directory caching can delay visibility of an AD change.
- Authentication is form-based; the browser never performs NTLM, SPNEGO, or Kerberos negotiation.
- JWTs use HMAC-SHA256, default to eight hours, and are accepted from the protected cookie or an `Authorization: Bearer` header. An active session entry in SQLite is also required. Logout removes that entry immediately, including for bearer-token reuse, and revocation survives restarts. Logout also works during directory outages. Existing sessions issued before this upgrade require a new login.
- Every POST requires `application/json`. Browser requests must originate from the exact configured HTTPS origin, derived from `WEB_HOSTNAME` and the external `WEB_HTTPS_PORT` (default 443), or explicitly listed in `WEB_TRUSTED_ORIGINS`. The service ignores Host and forwarded headers when determining trusted origins. Authenticated changes and logout require the session's `csrfToken` from login or `GET /api/session` in `X-CSRF-Token`. Login requires `X-CSRF-Token: login`; origin-less API clients must use an explicit bearer token and the session's CSRF token for authenticated changes. No cross-origin CORS access is granted.
- Login attempts are reserved atomically before authentication, with separate five-minute limits for client address and target account across client addresses. Successful logins consume a reservation and do not reset either limit. Case variations and the supported domain-qualified spellings of an account share a budget.
- TLS handshakes run in bounded connection workers, outside the accept loop, with a five-second timeout. Request I/O also has a timeout.
- Responses set HSTS, a restrictive Content Security Policy, clickjacking protection, and MIME sniffing protection. APIs and ordinary UI assets use no-store caching; pinned Typst compiler/font assets use immutable long-term caching.

### HTTPS and certificate management

The HTTP onboarding step accepts only an ACME directory URL without credentials, a hostname and an optional PEM root CA upload. Its setup code cannot access the HTTPS configuration API. HTTP rejects login, AD settings, backup settings and every administrative action. After onboarding, ordinary HTTP requests redirect to HTTPS; the ACME challenge route remains available for renewals. Challenges are forwarded to a loopback-only responder.

In `/admin/settings`, choose ACME, Smallstep CA, uploaded certificate/key PEM, or a self-signed certificate. ACME and CA credentials, custom trust roots, renewal intervals and uploaded private keys are entered over HTTPS. A temporary self-signed certificate keeps HTTPS setup reachable before managed issuance succeeds. Uploaded certificate/key pairs are validated before replacing working files. Certificate changes reload the HTTPS listener.

The client uses [`step ca certificate --acme --root --standalone`](https://smallstep.com/docs/step-cli/reference/ca/certificate/). Automatic ACME renewal checks default to every 900 seconds. If using a private CA, also install its root in clients' trust stores. Certificate provisioning errors leave the web setup available for correction.

## Backups

Configure backups entirely in `/admin/backup`: destination, automatic daily start hour (UTC), retention counts and optional encryption. Supported targets are rsync, SFTP, SMB and WebDAV; for example `sftp://backupuser:password@backup.example.com/exports/samba`. URL-encode reserved characters in credentials. Stored destination passwords are never returned to the browser; the UI shows only the protocol, server and path. Removing the destination disables future backups without deleting remote history.

Backups include Private files, active and archived Data folders, FSLogix, persistent server configuration/access records and Samba private state. Both SQLite databases use integrity-checked online snapshots. The rebuildable document index and previews, and retained trash, are omitted. Originals remain unchanged. The UI provides manual start, progress, current transfers and logs. Configuration and key changes are blocked while a backup is running.

When encryption is enabled, all sources—including credentials and server state—are staged as AES-256 7z archives with encrypted filenames/headers. Only encrypted archives and public format/key identifiers are uploaded. Generate a 24-word recovery phrase and confirm you recorded it before activating the key. It is displayed once, never persisted as a phrase, and expires after 15 minutes if not confirmed. The server retains the derived key so unattended backups work; protect the state volume and the Docker host accordingly. Encrypted staging requires space for a complete compressed backup.

Key renewal creates a separate `keys/<key-id>/snapshots/` generation. Existing backups stay in their previous location and require their previous phrase or legacy password. Retention affects only the active generation; older key generations are never pruned by a new key. Losing an old phrase or password makes that generation unrecoverable. Disabling encryption after using a generated key writes a separate `plain/` generation, keeping encrypted history separate. Existing installations retain their previous backup format/password until encryption is deliberately enabled or renewed.

Retention defaults are 3 daily, 2 weekly, 2 monthly and 1 yearly snapshots. Each tier selects its newest eligible snapshots; the union is kept. Snapshot names are UTC timestamps, and an incomplete upload is not marked complete. A interrupted job is detected from the backup lock rather than shown as running indefinitely.

To recover a generated-key archive offline, use `python3 app/restore_backup.py ARCHIVE.7z NEW_RECOVERY_DIRECTORY` with Python and 7z installed. The tool prompts for the phrase without echoing it, derives the key and extracts only into a new directory. Inspect the files before copying anything into live volumes. It refuses to overwrite an existing recovery directory. Legacy archives still use their original archive password.

The versioned key format is `adfs-backup-archive-v1`: standard BIP39 English phrase/checksum and seed derivation (empty BIP39 passphrase), then PBKDF2-HMAC-SHA512 with that seed as the password, ASCII salt `adfs-backup-archive-v1`, one iteration, 32-byte output, lowercase hexadecimal. This becomes the archive password used by 7z's own AES-256 key derivation. The key identifier is the first 24 hexadecimal characters of SHA-256 of that ASCII password. The wordlist and license are bundled, so offline recovery does not depend on a network service.

## Useful Commands

```bash
docker compose logs -f samba
docker compose logs -f samba | grep -E '\\[web\\]|\\[audit\\]'
docker compose exec samba python3 /app/reconcile_shares.py
docker compose exec samba python3 /app/run_service.py backup_to_destination.py
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

- Verify the stored domain-join/LDAP credentials in `/admin/settings`.
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
- Set the AD DNS registration address and name in `/admin/settings` → Server und DNS.
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
