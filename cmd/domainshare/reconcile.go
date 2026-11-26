package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/stuck-lehnert/domainshare/internal/accesscontrol"
	"github.com/stuck-lehnert/domainshare/internal/config"
	"github.com/stuck-lehnert/domainshare/internal/directory"
	"github.com/stuck-lehnert/domainshare/internal/reconcile"
	"github.com/stuck-lehnert/domainshare/internal/sambaacl"
	"github.com/stuck-lehnert/domainshare/internal/state"
	"golang.org/x/sys/unix"
)

func directoryReader(client directory.Client) func(context.Context, bool) (map[string]accesscontrol.Principal, map[string]accesscontrol.Principal, error) {
	cast := func(input map[string]directory.Principal) map[string]accesscontrol.Principal {
		result := make(map[string]accesscontrol.Principal, len(input))
		for key, row := range input {
			result[key] = accesscontrol.Principal{
				SID: row.SID, SAM: row.SAM, Name: row.Name, DN: row.DN, PrimaryRID: row.PrimaryRID, Members: row.Members,
			}
		}
		return result
	}
	return func(ctx context.Context, includeGroups bool) (map[string]accesscontrol.Principal, map[string]accesscontrol.Principal, error) {
		users, groups, err := client.Principals(ctx, includeGroups)
		if err != nil {
			return nil, nil, err
		}
		return cast(users), cast(groups), nil
	}
}

type configuredACLWriter struct{ root string }

func (writer configuredACLWriter) SetACLFD(ctx context.Context, target *os.File, descriptor sambaacl.Descriptor) error {
	name := filepath.Join(writer.root, "data-xattrs.tdb")
	db, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return fmt.Errorf("open trusted Samba xattr database: %w", err)
	}
	defer db.Close()

	return (sambaacl.Writer{HelperPath: "/usr/local/libexec/domainshare-sambaacl", Database: db}).SetACLFD(ctx, target, descriptor)
}

func newAccess(db *sql.DB, root string, env map[string]string, logf func(string, ...any)) (*accesscontrol.Service, error) {
	return accesscontrol.New(db, accesscontrol.Config{
		GroupRoot:   setting(env, "GROUP_ROOT", "/data/groups/data"),
		ArchiveRoot: setting(env, "GROUP_ARCHIVE_ROOT", "/data/groups/archive"),
		LockPath:    filepath.Join(root, "reconcile.lock"),
		AdminSID:    env["DOMAIN_ADMINS_SID"], ACLWriter: configuredACLWriter{root},
		ReadDirectory:        directoryReader(directoryClient(env)),
		CloseDataConnections: reconcile.CloseDataConnections, RepairACLs: repairDataACLs,
		Logf: logf,
	})
}

func repairDataACLs() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("REPAIR_DATA_ACLS"))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func runReconciliation(ctx context.Context, store *config.Store) error {
	trigger := strings.TrimSpace(os.Getenv("RECONCILE_TRIGGER"))
	if trigger == "" {
		trigger = "manual"
	}
	return reconcileShares(ctx, store, trigger, nil)
}

func reconcileShares(ctx context.Context, store *config.Store, trigger string, started func()) error {
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		return err
	}
	if snapshot.Phase != "configured" {
		return errors.New("complete setup before reconciling shares")
	}
	env, err := store.Environment(snapshot, false)
	if err != nil {
		return err
	}
	policy, err := state.OpenPrivate(ctx, env["STATE_DB_PATH"])
	if err != nil {
		return err
	}
	defer policy.Close()

	var output io.Writer = os.Stderr
	path := setting(env, "RECONCILE_LOG_FILE", "/var/log/reconcile.log")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0o600)
	if err == nil {
		defer file.Close()
		if info, err := file.Stat(); err == nil && info.Mode().IsRegular() {
			output = io.MultiWriter(os.Stderr, file)
		}
	}
	logger := log.New(output, "[reconcile] ", log.LstdFlags|log.LUTC)

	adminGID, err := directory.GroupID(ctx, env["DOMAIN_ADMINS_SID"])
	if err != nil {
		return errors.New("administrator group GID not available")
	}
	fslogixGID, err := directory.GroupID(ctx, env["FSLOGIX_GROUP_SID"])
	if err != nil {
		return errors.New("FSLogix group GID not available")
	}
	access, err := newAccess(policy, store.Root(), env, logger.Printf)
	if err != nil {
		return err
	}
	client := directoryClient(env)
	return reconcile.Run(ctx, reconcile.Options{
		Access: access, ReadDirectory: directoryReader(client), RepairACLs: repairDataACLs(),
		StatusPath: setting(env, "RECONCILE_STATUS_FILE", filepath.Join(store.Root(), "reconcile-status.json")),
		Trigger:    trigger, Logf: logger.Printf, OnStart: started,
		SyncFSLogix: func(context.Context) error {
			return reconcile.SyncFSLogix(setting(env, "FSLOGIX_ROOT", "/data/fslogix"), fslogixGID, adminGID)
		},
		SyncPrivate: func(ctx context.Context) error {
			return reconcile.SyncPrivate(ctx, reconcile.PrivateOptions{
				Root: setting(env, "PRIVATE_ROOT", "/data/private"), AdminGID: adminGID,
				Directory: client, IDs: directory.PrivateIDs, Logf: logger.Printf,
				SkipUsers: os.Getenv("PRIVATE_SKIP_USERS"), SkipPrefix: os.Getenv("PRIVATE_SKIP_PREFIXES"),
			})
		},
	})
}
