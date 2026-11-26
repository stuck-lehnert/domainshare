# Managed Samba ACLs

`NewDescriptor(levels map[string]int, adminSID string, options Options)`
returns an immutable `Descriptor`. Pass `Options{}` for a regular file,
`Options{Directory: true}` for a descendant directory,
`Options{Directory: true, TopLevel: true}` for a managed top-level directory,
or `Options{Directory: true, ShareRoot: true}` with no assignments for the
Data share root. `Descriptor.SDDL()` gives the matching diagnostic SDDL;
`Descriptor.Pack() ([]byte, error)` gives the Samba NDR `security.NTACL` v1
bytes. Neither function needs Samba or Python at runtime.

`Writer{HelperPath: absolutePath, Database: dbFile}.SetACLFD(ctx, target,
descriptor)` writes to the supplied pinned data inode. Open the database
read-write in the trusted state directory with `O_NOFOLLOW` and mode 0600
if creating it. The DB inode must be regular, owned by the writer, and have
one directory entry. Keep the database and target descriptors open until
the call completes. The target must already have been opened and validated
as a managed regular file or directory without following symlinks. Do not
use `O_PATH` for the target because the legacy ownership and mode changes
require a usable file descriptor.

The helper receives only data FD 3, database FD 4, the expected target kind,
and the packed descriptor on stdin. It uses `fstat(3)` to identify the data
inode and opens only the existing database inode through `/proc/self/fd/4`.
Samba performs the actual record locking and xattr serialization. No code in
this package looks up a production database by name or edits TDB records
directly. The DB must be the same local persistent `xattr_tdb:file` used by
the Data share. Non-default TDB flags and clustered databases are not
supported by this bridge.

Ownership, ACL and local mode are not one transaction: a failure can follow
an earlier successful step. Only publish the restored file or persist an ACL
success signature if `SetACLFD` returns nil. A request cancellation does not
kill the helper after a write has started. Local data mounts must remain
container-private, as in the Python implementation.

## Debian 12 build and runtime

On Bookworm, the helper build needs `gcc` and `libc6-dev`; it does not need
Samba headers or Go cgo. Compile in a Debian 12 build stage:

```sh
cc -std=gnu11 -O2 -Wall -Wextra -Werror \
  "-DSAMBA_PRIVATE_DIR=\"/usr/lib/$(gcc -print-multiarch)/samba\"" \
  internal/sambaacl/helper/main.c -o domainshare-sambaacl -ldl
```

Install the executable at a trusted absolute path, such as
`/usr/local/libexec/domainshare-sambaacl`. The runtime needs `libc6`, mounted
`/proc`, and Bookworm `samba-libs` with its dependencies. The serving Samba
installation also needs `samba` and `samba-vfs-modules` as before.
`SetACLFD` needs permission to change target ownership to root:root.

The helper requires the private, versioned Bookworm ABI
`SAMBA_4.17.12_DEBIAN_SAMBA4` in `libxattr-tdb-samba4.so.0`; it refuses an
incompatible library. The ABI was exercised against the official amd64
`samba-libs` package `4.17.12+dfsg-0+deb12u4`. Re-run the integration test
before changing Samba distribution or package series. The package does not
invoke Python in production.

## Verification

```sh
go test -race ./internal/sambaacl
# Compile the helper as above on Bookworm, then run against temporary fixtures:
DOMAINSHARE_ACL_TEST_HELPER="$PWD/domainshare-sambaacl" \
  go test -race -count=1 -run TestBookwormPinnedInodeStorage ./internal/sambaacl
```

The integration check needs `python3-samba` only as an independent verifier.
When using extracted Bookworm libraries on another distribution, point
`SAMBA_PRIVATE_DIR` and `LD_LIBRARY_PATH` at the extracted libraries; the
test removes that loader override from the Python verifier. All test writes
go to `t.TempDir()`: the test initializes a new DB, writes an unrelated EA
with Samba, renames the data file, and verifies that the ACL is updated only
on the original pinned inode and the other EA is preserved. The verification
also checks the final target mode when run as root; an unprivileged test
exercises the same storage bridge without changing target ownership.

The five `testdata/python-ntacl-v1.json` cases were generated with the original
Python `app.access_control.descriptor` and `pack_descriptor` using Samba's
NDR serializer. They cover file and directory inheritance, level 0, rights
for admins and other principals, the top-level `DELETE` split, and the
non-inheritable Authenticated Users read grant at the Data share root.
