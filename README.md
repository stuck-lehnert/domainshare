# AD-Integrated Containerized Samba File Server

This repository provides a production-oriented Samba file server container that joins an existing Active Directory domain and exposes three SMB shares: `Private`, `Data`, and `FSLogix`.

## Architecture

- Samba runs in ADS mode with `winbind` identity mapping.
- Static shares:
  - `\\server\Private` -> `/data/private`
  - `\\server\Data` -> `/data/groups/data`
  - `\\server\FSLogix` -> `/data/fslogix`
- FS_* groups are projected as folders inside the Data share (`/data/groups/data/<groupName>`).
- Group records are persisted in SQLite at `/state/shares.db`.
- Group folders are name-based while active and moved to archive on deactivation:
  - active: `/data/groups/data/<groupName>`
  - inactive/deleted groups: `/data/groups/archive/<groupName>`
- Samba machine trust/key material is persisted in `/var/lib/samba` to survive container recreation.
- Container hostname is fixed (`SAMBA_HOSTNAME`) to keep AD computer identity stable.
- NetBIOS name defaults to `ADSAMBAFSRV` and is clamped to 15 characters (`NETBIOS_NAME` override supported).
- Setup prompts for well-known authorization groups by SID (`DOMAIN_USERS_SID`, `DOMAIN_ADMINS_SID`) to avoid localized group names.
- `FSLOGIX_GROUP_SID` controls who can access the default FSLogix share (defaults to `DOMAIN_USERS_SID`).
- Startup resolves those SIDs to NSS group names via winbind, then uses those resolved groups in Samba `valid users` rules.
- Share operations are audited with Samba `full_audit` (connect, list, read, write, create, delete, rename) and written to Samba log files.
- Optional remote backups run when `BACKUP_DESTINATION` is configured.
- Private home creation skips well-known/service accounts by default (including `krbtgt`, `msol_*`, `FileShare_ServiceAcc`).
- Reconciliation is executed:
  - once on startup
  - every 5 minutes via cron
- Backup is executed:
  - daily at `BACKUP_START_HOUR` (default: `2`, i.e. 02:00)

## Data Folder Lifecycle

The reconciliation script (`/app/reconcile_shares.py`) enforces these rules:

1. New matching `FS_*` group -> insert DB row and create `/data/groups/data/<groupName>`.
2. Group rename while still matching `FS_*` -> rename/update folder path.
3. Group removed or no longer matching `FS_*` -> set `isActive=0` and move folder to `/data/groups/archive/...`.
4. Previously inactive group returns -> set `isActive=1`, move back into `/data/groups/data/...`.

## SQLite State Database

Database path: `/state/shares.db`

Table schema:

```sql
CREATE TABLE shares (
  objectGUID TEXT PRIMARY KEY,
  samAccountName TEXT NOT NULL,
  shareName TEXT NOT NULL,
  path TEXT NOT NULL,
  createdAt TIMESTAMP NOT NULL,
  lastSeenAt TIMESTAMP NOT NULL,
  isActive INTEGER NOT NULL
);
```

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
- `etc/samba/smb.conf`

## Setup

1. Run interactive setup:

   ```bash
   ./setup
   ```

2. If `.env` is missing, you will be prompted for:
   - `REALM`
   - `WORKGROUP`
   - `DOMAIN`
   - initial admin credentials (used once for provisioning)
   - `DOMAIN_USERS_SID`
   - `DOMAIN_ADMINS_SID`
   - optional `FSLOGIX_GROUP_SID` (defaults to `DOMAIN_USERS_SID`)
   - optional `BACKUP_DESTINATION` (empty disables backup)
   - optional `BACKUP_START_HOUR` (0-23, default `2`)
   - optional `BACKUP_RETENTION_DAILY` (default `3`)
   - optional `BACKUP_RETENTION_WEEKLY` (default `2`)
   - optional `BACKUP_RETENTION_MONTHLY` (default `2`)
   - optional `BACKUP_RETENTION_YEARLY` (default `1`)

   Optional:
   - `SAMBA_HOSTNAME` (defaults to `adsambafsrv`)
   - `NETBIOS_NAME` (defaults to `ADSAMBAFSRV`, max 15 chars)

3. Setup behavior:
   - creates or updates AD service account from desired name `FileShare_ServiceAccount`
   - uses a valid AD `sAMAccountName` (max 20 chars); default effective value is `FileShare_ServiceAcc`
   - always sets a long random password
   - writes only service-account credentials to `.env` (initial admin credentials are not stored)

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
- No guest access.

### FSLogix

- Share: `\\server\FSLogix`
- Path: `/data/fslogix`
- Access for authenticated users in configurable `FSLOGIX_GROUP_SID` (default: `DOMAIN_USERS_SID`, resolved through winbind).
- Semantics intentionally differ from `Data`: only the share root is reconciled (`03770` + ACL defaults), while user-created profile container folders/files are not recursively normalized.
- Samba masks are profile-container oriented (`create mask = 0600`, `directory mask = 0700`) so profile payload stays user-private by default.

## Backups

- Backups are enabled only if `BACKUP_DESTINATION` is non-empty.
- Each run creates a timestamped snapshot under `snapshots/YYYYMMDDTHHMMSSZ` at the destination.
- Backup job is scheduled daily at `BACKUP_START_HOUR` in container local time.
- Sources synced to destination on each run:
  - `/data/private` -> `data/private`
  - `/data/groups` -> `data/groups`
  - `/data/fslogix` -> `data/fslogix`
  - `/state` -> `state`
  - `/var/lib/samba/private` -> `samba/private`
- Retention policy env vars (defaults):
  - `BACKUP_RETENTION_YEARLY=1`
  - `BACKUP_RETENTION_MONTHLY=2`
  - `BACKUP_RETENTION_WEEKLY=2`
  - `BACKUP_RETENTION_DAILY=3`
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
  BACKUP_START_HOUR=2
  BACKUP_RETENTION_DAILY=3
  BACKUP_RETENTION_WEEKLY=2
  BACKUP_RETENTION_MONTHLY=2
  BACKUP_RETENTION_YEARLY=1
  ```

## Useful Commands

```bash
docker compose logs -f samba
docker compose exec samba python3 /app/reconcile_shares.py
docker compose exec samba sqlite3 /state/shares.db 'SELECT * FROM shares;'
docker compose exec samba testparm -s
docker compose exec samba sh -lc 'tail -n 200 /var/log/samba/log.*'
docker compose exec samba sh -lc 'tail -n 200 /var/log/backup.log'
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
