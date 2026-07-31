#!/usr/bin/env bash
set -Eeuo pipefail

: "${BACKUP_USERNAME:?missing BACKUP_USERNAME}"
: "${BACKUP_PASSWORD:?missing BACKUP_PASSWORD}"
backup_base_dir=${BACKUP_BASE_DIR:-fileserver}

mkdir -p "/backup/${backup_base_dir}/snapshots"

cat > /etc/rsyncd.conf <<EOF
uid = root
gid = root
use chroot = no
max connections = 8
pid file = /run/rsyncd.pid
lock file = /run/rsyncd.lock
log file = /dev/stdout
timeout = 300

[backups]
path = /backup
read only = false
list = true
auth users = ${BACKUP_USERNAME}
secrets file = /etc/rsyncd.secrets
EOF

printf '%s:%s\n' "$BACKUP_USERNAME" "$BACKUP_PASSWORD" > /etc/rsyncd.secrets
chmod 0600 /etc/rsyncd.secrets

printf '[preview-backup] rsync://0.0.0.0/backups ready\n'
exec rsync --daemon --no-detach --config=/etc/rsyncd.conf
