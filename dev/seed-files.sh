#!/usr/bin/env bash
set -Eeuo pipefail

seed_mb=${DEV_SEED_MB:-8}

mkdir -p \
  /data/groups/data/Finance/Reports \
  /data/groups/data/Engineering/Designs \
  /data/groups/data/Projects/Planning \
  /data/private/alice \
  /data/private/bob \
  /data/private/carol \
  /data/private/dave \
  /data/private/eve \
  /data/fslogix/alice_S-1-5-21-111-222-333-1101 \
  /data/fslogix/carol_S-1-5-21-111-222-333-1103

printf 'Quarter,Forecast\nQ1,120000\nQ2,135000\n' > /data/groups/data/Finance/Reports/forecast.csv
printf '# Architecture\n\nPreview design notes.\n' > /data/groups/data/Engineering/Designs/architecture.md
printf 'Milestone,Owner\nDiscovery,Eve\nDelivery,Carol\n' > /data/groups/data/Projects/Planning/roadmap.csv
printf 'Alice private preview data.\n' > /data/private/alice/readme.txt
printf 'Bob private preview data.\n' > /data/private/bob/readme.txt
printf 'Carol private preview data.\n' > /data/private/carol/readme.txt
printf 'Dummy FSLogix profile for Alice.\n' > /data/fslogix/alice_S-1-5-21-111-222-333-1101/profile.vhdx
printf 'Dummy FSLogix profile for Carol.\n' > /data/fslogix/carol_S-1-5-21-111-222-333-1103/profile.vhdx

dd if=/dev/zero of=/data/groups/data/Finance/Reports/history.bin bs=1M count="$seed_mb" status=none
dd if=/dev/zero of=/data/groups/data/Engineering/Designs/models.bin bs=1M count="$seed_mb" status=none
dd if=/dev/zero of=/data/fslogix/alice_S-1-5-21-111-222-333-1101/profile-data.bin bs=1M count="$seed_mb" status=none


printf '[preview-seed] Seeded group, private, and FSLogix data.\n'

# Seed the old state layout to exercise the one-time migration on startup.
python3 - <<'PYSEED'
import sqlite3
conn = sqlite3.connect('/state/shares.db')
conn.execute("CREATE TABLE shares (objectGUID TEXT PRIMARY KEY, samAccountName TEXT NOT NULL, shareName TEXT NOT NULL, path TEXT NOT NULL, createdAt TEXT NOT NULL, lastSeenAt TEXT NOT NULL, isActive INTEGER NOT NULL DEFAULT 1)")
for name in ('Finance', 'Engineering', 'Projects'):
    conn.execute("INSERT INTO shares VALUES(?,?,?,?,?,?,1)", (name, 'FS_' + name, name, '/data/groups/data/' + name, '2026-01-01', '2026-01-01'))
conn.commit()
PYSEED
