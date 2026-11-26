# Managed Data folder permissions

`New(db, Config{...})` leaves the SQLite handle and any Samba writer/DB
descriptors owned by the caller. Use a shared SQLite handle configured with
foreign keys, WAL, and a busy timeout. Call `EnsureSchema(ctx)` once before
read-only `Snapshot(ctx, current)`, `Report(ctx)`, or `EffectiveLevels(ctx, id)`
calls. `WithMutation` also ensures the schema while holding the lock. The
`access_changes` table remains the durable admin action history.

## Runtime dependencies

* `GroupRoot` and `ArchiveRoot` are distinct sibling directories; defaults are
  `/data/groups/data` and `/data/groups/archive`. `LockPath` defaults to
  `/state/reconcile.lock` and must be shared by all legacy and native writers.
* Supply the AD administrator SID and `ACLWriter`, normally
  `sambaacl.Writer` backed by a caller-managed open TDB descriptor. This package
  never opens the TDB or runs `smbcontrol` itself.
* `ReadDirectory(ctx, includeGroups)` returns users keyed by SID and groups
  keyed by normalized DN. `Principal.Members` must contain normalized DNs;
  use `PrimaryRID: -1` for a missing primary group. Only first-time migration
  requests legacy groups. `ApplyChange` will fetch current users under the
  lock if the `current` argument is nil. Use `json.Decoder.UseNumber()` when
  decoding update bodies so fractional or exponent-form levels are rejected.
* Set `RepairACLs` to return true when policy requires recursive repair, or
  explicitly call `SyncPermissions(ctx, true)` after detecting a new ACL DB.
  This package does not inspect that database to infer whether it is new.
* `CloseDataConnections(ctx)` disconnects Data clients. `Logf` lets the caller
  capture migration and recovery messages. Managed path traversal requires
  Linux `openat2` and `/proc`; it rejects symlinks, unsupported file kinds and
  mount crossings below the configured roots instead of falling back.

## Lock and operation order

Use `Service.ApplyChange(ctx, body, actor, current)` for a web mutation. It
acquires the shared lock itself. A busy lock or existing move destination
returns `accesscontrol.Conflict`. Request validation errors use
`accesscontrol.Invalid`; use `errors.As` to distinguish them.

Native reconcile should run the following under one
`Service.WithMutation(ctx, func(m *accesscontrol.Mutation) error { ... })`:

1. `m.Migrate(ctx)` imports once and resumes legacy folder layouts.
2. Fetch current users without groups, then `m.CacheUsers(ctx, users)`.
3. `m.RecoverPending(ctx)` repairs any interrupted policy/layout-independent
   ACL operation. A recovery failure retains its marker.
4. `m.SyncPermissions(ctx, force)` writes ACLs through pinned descriptors and
   commits signatures. This does **not** close SMB connections.
5. `m.CloseDataConnections(ctx, false)` closes clients if revocation or
   recovery left a retry marker. Admin changes queue a disconnect durably
   before attempting it, so a disconnect error does not roll back the already
   stored policy and a later reconciliation can retry.

On trash restore, pass `m.PrepareDataRestore` to `trash.Service.Restore`
inside the same callback. Keep the lock across the whole restore including
publication, not just ACL preparation. Recover pending changes first. The
callback checks the active stored folder and its pinned destination directory
chain, programs those directories and the pinned source, and never closes
borrowed descriptors. Do not retain the `Mutation` or reacquire the lock from
within its callback.

## Verification

`go test -race ./internal/accesscontrol` uses temporary filesystem and SQLite
fixtures, an ACL recorder and a fake share closer. It does not require AD,
SMB, a TDB, root, or production data.
