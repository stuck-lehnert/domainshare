package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"time"

	"github.com/stuck-lehnert/domainshare/internal/accesscontrol"
	"github.com/stuck-lehnert/domainshare/internal/securefile"
)

type Options struct {
	Access        *accesscontrol.Service
	ReadDirectory func(context.Context, bool) (map[string]accesscontrol.Principal, map[string]accesscontrol.Principal, error)
	SyncFSLogix   func(context.Context) error
	SyncPrivate   func(context.Context) error
	RepairACLs    bool
	StatusPath    string
	Trigger       string
	Logf          func(string, ...any)
	OnStart       func()
}

type status struct {
	State       string  `json:"state"`
	Percent     int     `json:"percent"`
	Phase       string  `json:"phase"`
	Trigger     string  `json:"trigger"`
	StartedAt   string  `json:"startedAt"`
	UpdatedAt   string  `json:"updatedAt"`
	FinishedAt  *string `json:"finishedAt"`
	CurrentItem *string `json:"currentItem"`
	Message     string  `json:"message"`
}

func (options Options) publish(value status) {
	if options.StatusPath == "" {
		return
	}
	value.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	data, err := json.Marshal(value)
	if err == nil {
		err = securefile.WritePrivate(options.StatusPath, data)
	}
	if err != nil && options.Logf != nil {
		options.Logf("Unable to write reconciliation status: %v", err)
	}
}

// Run keeps the same flock as the legacy reconciliation until all Data, Private
// and FSLogix changes are committed. A contending run does not replace status.
func Run(ctx context.Context, options Options) error {
	if options.Access == nil || options.ReadDirectory == nil || options.SyncFSLogix == nil || options.SyncPrivate == nil {
		return errors.New("incomplete reconciliation configuration")
	}
	return options.Access.WithMutation(ctx, func(mutation *accesscontrol.Mutation) (failure error) {
		started := time.Now()
		value := status{State: "starting", Phase: "starting", Trigger: options.Trigger,
			StartedAt: started.UTC().Format(time.RFC3339), Message: "Starting reconciliation"}
		options.publish(value)
		if options.OnStart != nil {
			options.OnStart()
		}
		defer func() {
			finished := time.Now().UTC().Format(time.RFC3339)
			value.FinishedAt = &finished
			if failure != nil {
				value.State, value.Phase, value.Message = "failed", "failed", "Reconciliation did not complete"
			} else {
				value.State, value.Phase, value.Percent = "completed", "completed", 100
				value.Message = fmt.Sprintf("Reconciliation completed in %s", time.Since(started).Round(time.Millisecond))
			}

			// The status endpoint reads the log alongside the status. Write the
			// terminal line first so it is already visible on completion.
			if options.Logf != nil {
				options.Logf("%s", value.Message)
			}
			options.publish(value)
		}()

		progress := func(percent int, phase, description string) {
			value.State, value.Percent, value.Phase, value.Message = "running", percent, phase, description
			options.publish(value)
			if options.Logf != nil {
				options.Logf("%s", description)
			}
		}

		progress(2, "winbind", "Refreshing winbind cache")
		if err := command(ctx, 15*time.Second, "net", "cache", "flush"); err != nil && options.Logf != nil {
			options.Logf("Winbind cache refresh failed; membership changes may be delayed")
		}

		progress(10, "database", "Loading admin-managed folders")
		if err := mutation.EnsureSchema(ctx); err != nil {
			return err
		}
		if err := mutation.Migrate(ctx); err != nil {
			return err
		}
		users, _, err := options.ReadDirectory(ctx, false)
		if err != nil {
			return err
		}
		if err := mutation.CacheUsers(ctx, users); err != nil {
			return err
		}
		if err := mutation.RecoverPending(ctx); err != nil {
			return err
		}

		progress(32, "data-permissions", "Syncing managed folder permissions")
		if err := mutation.SyncPermissions(ctx, options.RepairACLs); err != nil {
			return err
		}
		if err := mutation.CloseDataConnections(ctx, false); err != nil {
			return err
		}

		progress(76, "fslogix", "Syncing FSLogix root")
		if err := options.SyncFSLogix(ctx); err != nil {
			return err
		}
		progress(84, "private", "Syncing private directories")
		if err := options.SyncPrivate(ctx); err != nil {
			return err
		}

		progress(96, "samba", "Reloading Samba config")
		if err := command(ctx, 15*time.Second, "smbcontrol", "all", "reload-config"); err != nil && options.Logf != nil {
			options.Logf("Samba configuration reload failed; will retry on the next run")
		}
		return ctx.Err()
	})
}

func CloseDataConnections(ctx context.Context) error {
	return command(ctx, 15*time.Second, "smbcontrol", "all", "close-share", "Data")
}

func command(ctx context.Context, timeout time.Duration, binary string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return exec.CommandContext(ctx, binary, args...).Run()
}
