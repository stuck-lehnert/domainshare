# AD-Integrated Containerized Samba File Server

This repository provides a production-oriented Samba file server container that joins an existing Active Directory domain, exposes static and dynamic SMB shares, and persists share identity by AD `objectGUID`.

## Architecture

- Samba runs in ADS mode with `winbind` identity mapping.
- Static shares:
  - `\\server\Privat` -> `/data/private`
  - `\\server\Geteilt` -> `/data/public`
- Dynamic shares are generated from AD groups matching `FileShare_*` or `FS_*` and written to `/etc/samba/generated/shares.conf`.
- Dynamic share records are persisted in SQLite at `/state/shares.db`.
- Backing storage is GUID-based and stable across group rename:
  - `/data/groups/<objectGUID>`
- Samba machine trust/key material is persisted in `/var/lib/samba` to survive container recreation.
- Container hostname is fixed (`SAMBA_HOSTNAME`) to keep AD computer identity stable.
- NetBIOS name defaults to `ADSAMBAFSRV` and is clamped to 15 characters (`NETBIOS_NAME` override supported).
- Setup prompts for well-known authorization groups by SID (`DOMAIN_USERS_SID`, `DOMAIN_ADMINS_SID`) to avoid localized group names.
- Startup resolves those SIDs to NSS group names via winbind, then uses those resolved groups in Samba `valid users` rules.
- Share operations are audited with Samba `full_audit` (connect, list, read, write, create, delete, rename) and written to Samba log files.
- Private home creation skips well-known/service accounts by default (including `krbtgt`, `msol_*`, `FileShare_ServiceAcc`).
- Reconciliation is executed:
  - once on startup
  - every 5 minutes via cron

## Dynamic Share Lifecycle (objectGUID-first)

The reconciliation script (`/app/reconcile_shares.py`) enforces these rules:

1. New matching group -> insert DB row, create `/data/groups/<objectGUID>`, expose share.
2. Group renamed but still `FileShare_` -> update `samAccountName` and `shareName`, keep same path.
3. Group removed or no longer matches prefix -> set `isActive=0`, remove Samba exposure, keep data.
4. Previously inactive group returns -> set `isActive=1`, reuse existing path and data.

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
- Group naming convention for dynamic shares:
  - `FileShare_<ShareName>` or `FS_<ShareName>`

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
- `etc/samba/smb.conf`
- `etc/samba/generated/`

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
   - optional `PUBLIC_GROUP_SID` (defaults to `DOMAIN_USERS_SID`)

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

### Privat

- Share: `\\server\Privat`
- Root path: `/data/private`
- Per-user path: `/data/private/<samAccountName>`
- Script ensures user directories exist and assigns ownership through winbind identity resolution.
- Root `/data/private` is enforced read/execute-only (`0555`) to prevent folder creation directly under `\\server\Privat`.
- SMB-side ACL changes on `\\server\Privat` are blocked (`nt acl support = no`).
- Auto-creation skips well-known/service/non-login accounts (disabled, locked, or expired).
- Each private user tree is reconciled recursively to homogeneous permissions (dirs `0700`, files `0600`, user/admin ACLs).
- Permissions:
  - owner user: full control
  - Domain Admins: ACL full control
  - mode: `700`
- `hide unreadable = yes` + ACLs enforce that users only see their own folder.

### Geteilt

- Share: `\\server\Geteilt`
- Path: `/data/public`
- Read/write for authenticated users in configurable `PUBLIC_GROUP_SID` (default: `DOMAIN_USERS_SID`, resolved through winbind).
- No guest access.
- Permissions are reconciled recursively so all descendants remain homogeneous (dirs `2770`, files `0660`, shared group/admin ACLs).

### Dynamic Group Shares

- AD groups: `FileShare_*` and `FS_*`
- Share name: group title from AD (`displayName` -> `name`/`cn` fallback). Prefix stripping from `sAMAccountName` is only a fallback when no title exists.
- Backing path: `/data/groups/<objectGUID>`
- Share exposure generated in `/etc/samba/generated/shares.conf`
- Dynamic share names are validated for SMB compatibility and deduplicated case-insensitively.
- Group membership changes are refreshed continuously via winbind cache updates (`winbind cache time = 60`) and Samba config reload during reconciliation.
- Dynamic share trees are reconciled recursively so all descendants keep homogeneous permissions.

## Useful Commands

```bash
docker compose logs -f samba
docker compose exec samba python3 /app/reconcile_shares.py
docker compose exec samba sqlite3 /state/shares.db 'SELECT * FROM shares;'
docker compose exec samba testparm -s
docker compose exec samba sh -lc 'tail -n 200 /var/log/samba/log.*'
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

### Dynamic shares not appearing

- Confirm AD groups match `FileShare_*` or `FS_*`.
- Run manual reconciliation and inspect logs:

  ```bash
  docker compose exec samba python3 /app/reconcile_shares.py
  docker compose exec samba tail -n 100 /var/log/reconcile.log
  ```

- Validate generated config:

  ```bash
  docker compose exec samba cat /etc/samba/generated/shares.conf
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

### Permissions in Privat share are incorrect

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
- Inactive/deleted groups only stop being exposed as shares.
- Data and state survive container restarts via named Docker volumes (`/data/*`, `/state`, `/var/lib/samba`).
