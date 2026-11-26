# Samba recycle bin

`New(OptionsFromEnv(os.LookupEnv))` uses the existing `GROUP_ROOT`,
`PRIVATE_ROOT`, `FSLOGIX_ROOT` and `TRASH_RETENTION_DAYS` settings. `List`,
`OpenDownload` and `Restore` use the existing item IDs and JSON field names.
The web layer still owns authentication, HTTP error mapping and the existing
restore audit log. It can distinguish `InvalidError`, `fs.ErrNotExist`,
`fs.ErrExist`, and `ErrDataACLRequired` with `errors.As`/`errors.Is`.

## Data restore

The parent web/ACL integration owns wiring `Service.Restore(ctx, id, prepare)`
to the native Samba ACL service. The reviewed callback contract is
`type DataRestoreACL func(context.Context, DataRestoreTarget) error`, where
`DataRestoreTarget` carries `RelativePath string`, `Source *os.File` and
`Directories []*os.File`. For Data, callers must hold the same mutation lock
used for ACL changes across the entire `Restore` call. The callback uses the
existing `shares.db` connection to look up `shares WHERE shareName=? AND
isActive=1`, verifies that the active record corresponds to the first opened
directory, and applies current ACLs to the supplied inodes. It returns an
error on any failure; there is no mode-only fallback. The trash package does
not open the database or change ACLs on existing directories. `Directories`
is ordered from the managed group directory to the destination parent, and all
descriptors are borrowed only during the callback.

The top-level Data group must already exist. Missing nested parents are created
with mode `0700`, owned by the worker, before the callback. The file is not yet
visible at its destination. On failure, the worker returns it to trash and tries
to remove only directories it created, deepest first, and only if they are still
the same inode and empty. It leaves existing directories and any directory that
now contains another file alone. Data file inodes with multiple hard links are
rejected before ACL preparation, so another link does not receive that ACL change.
Private and FSLogix do not use the callback; new parents keep the source file's
UID/GID and mode `0700`.

Restore relies on Linux `renameat2(RENAME_NOREPLACE)` support for the filesystem.
It moves the file through a private `.domainshare-restore-*` directory in the
recycle bin, then publishes the same inode without overwriting an existing name.
If the worker is interrupted or another entry prevents rollback, the original
inode is preserved as `item` in that stage with its recycle-bin relative path
in `origin.json`. Normal listing, download, and retention skip this reserved
namespace. An administrator must inspect such a leftover stage and resolve any
name conflict before returning the entry to trash.

The optional `domainshare-trash --cleanup` runs one retention pass and prints
the existing worker's summary. It is not wired into production yet.
