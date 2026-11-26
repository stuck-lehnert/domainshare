package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/stuck-lehnert/domainshare/internal/audit"
	"github.com/stuck-lehnert/domainshare/internal/backup"
	"github.com/stuck-lehnert/domainshare/internal/config"
	"github.com/stuck-lehnert/domainshare/internal/state"
	"github.com/stuck-lehnert/domainshare/internal/trash"
)

func lookup(env map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		value, ok := env[key]
		return value, ok
	}
}

func configuredEnv(ctx context.Context, store *config.Store) (config.Snapshot, map[string]string, error) {
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		return snapshot, nil, err
	}
	if snapshot.Phase != "configured" {
		return snapshot, nil, errors.New("complete setup before running this worker")
	}
	env, err := store.Environment(snapshot, false)
	return snapshot, env, err
}

func runAuditCollector(ctx context.Context, store *config.Store) error {
	_, env, err := configuredEnv(ctx, store)
	if err != nil {
		return err
	}

	db, err := state.OpenPrivate(ctx, env["STATE_DB_PATH"])
	if err != nil {
		return err
	}
	defer db.Close()

	storeAudit, err := audit.NewStore(ctx, db)
	if err != nil {
		return err
	}
	collector, err := audit.NewCollectorWithEnv(storeAudit, lookup(env))
	if err != nil {
		return err
	}
	return collector.Run(ctx)
}

func runTrashCleanup(ctx context.Context, store *config.Store) error {
	_, env, err := configuredEnv(ctx, store)
	if err != nil {
		return err
	}
	service, err := trash.New(trash.OptionsFromEnv(lookup(env)))
	if err != nil {
		return err
	}
	result, err := service.Cleanup(ctx, time.Time{})
	if err != nil {
		return err
	}
	fmt.Printf("[trash] Removed %d expired or excluded item(s) (%d bytes)\n", result.Removed, result.RemovedBytes)
	return nil
}

func backupOptions(env map[string]string, trigger string) backup.Options {
	options := backup.OptionsFromEnv(lookup(env))
	options.StatusPath = setting(env, "BACKUP_STATUS_FILE", options.StateRoot+"/backup-status.json")
	options.Trigger = trigger
	return options
}

func runBackup(ctx context.Context, store *config.Store, slot string) error {
	return backup.RunConfigured(ctx, store.Root(), func() (backup.Options, error) {
		snapshot, env, err := configuredEnv(ctx, store)
		if err != nil {
			return backup.Options{}, err
		}

		trigger := "manual"
		if slot != "" {
			now := time.Now().UTC()
			const layout = "2006-01-02T15"
			if now.Format(layout) != slot || !snapshot.Values.Bool("BACKUP_AUTO_ENABLED") ||
				snapshot.Values.Int("BACKUP_START_HOUR") != now.Hour() || env["BACKUP_DESTINATION"] == "" {
				return backup.Options{StateRoot: store.Root()}, nil
			}
			claimed, err := store.ClaimBackupSlot(ctx, slot)
			if err != nil || !claimed {
				return backup.Options{StateRoot: store.Root()}, err
			}
			trigger = "automatic"
		}
		return backupOptions(env, trigger), nil
	})
}
