# AD-Integrated Containerized Samba File Server

This repository provides a production-oriented Samba file server container that joins an existing Active Directory domain, exposes static and dynamic SMB shares, and persists share identity by AD `objectGUID`.

## Architecture

- Samba runs in ADS mode with `winbind` identity mapping.
- Static shares:
  - `\\server\Private` -> `/data/private`
  - `\\server\Public` -> `/data/public`
- Dynamic shares are generated from AD groups matching `FileShare_*` and written to `/etc/samba/generated/shares.conf`.
- Dynamic share records are persisted in SQLite at `/state/shares.db`.
- Backing storage is GUID-based and stable across group rename:
  - `/data/groups/<objectGUID>`
- Samba machine trust/key material is persisted in `/var/lib/samba` to survive container recreation.
- Container hostname is fixed (`SAMBA_HOSTNAME`) to keep AD computer identity stable.
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
- A service account with rights to join computers to the domain (`net ads join`).
- Dynamic group discovery primarily uses machine-account LDAP (`net ads search -P`); join credentials are only used as a fallback LDAP bind path.
- Group naming convention for dynamic shares:
  - `FileShare_<ShareName>`

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
   - `JOIN_USER`
   - `JOIN_PASSWORD`

3. The setup script writes `.env` and starts the service with:

   ```bash
   docker compose up -d
   ```

4. After startup:
   - container joins AD (idempotent)
   - startup reconciliation runs
   - cron runs reconciliation every 5 minutes

## SMB Shares

### Private

- Share: `\\server\Private`
- Root path: `/data/private`
- Per-user path: `/data/private/<samAccountName>`
- Script ensures user directories exist and assigns ownership through winbind identity resolution.
- Permissions:
  - owner user: full control
  - Domain Admins: ACL full control
  - mode: `700`
- `hide unreadable = yes` + ACLs enforce that users only see their own folder.

### Public

- Share: `\\server\Public`
- Path: `/data/public`
- Read/write for authenticated users in configurable `PUBLIC_GROUP` (default `Domain Users`).
- No guest access.

### Dynamic Group Shares

- AD groups: `FileShare_*`
- Share name: prefix removed (`FileShare_Finance` -> `\\server\Finance`)
- Backing path: `/data/groups/<objectGUID>`
- Share exposure generated in `/etc/samba/generated/shares.conf`
- Dynamic share names are validated for SMB compatibility and deduplicated case-insensitively.

## Useful Commands

```bash
docker compose logs -f samba
docker compose exec samba python3 /app/reconcile_shares.py
docker compose exec samba sqlite3 /state/shares.db 'SELECT * FROM shares;'
docker compose exec samba testparm -s
```

## Troubleshooting

### Domain join fails

- Verify credentials in `.env`.
- Verify DNS resolution from container:

  ```bash
  docker compose exec samba getent hosts "$DOMAIN"
  ```

- Verify time sync on host and AD DCs.

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

- Confirm AD groups match `FileShare_*`.
- Run manual reconciliation and inspect logs:

  ```bash
  docker compose exec samba python3 /app/reconcile_shares.py
  docker compose exec samba tail -n 100 /var/log/reconcile.log
  ```

- Validate generated config:

  ```bash
  docker compose exec samba cat /etc/samba/generated/shares.conf
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
- Inactive/deleted groups only stop being exposed as shares.
- Data and state survive container restarts via named Docker volumes (`/data/*`, `/state`, `/var/lib/samba`).
