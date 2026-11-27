package supervisor

import (
	"context"
	"time"

	"github.com/stuck-lehnert/domainshare/internal/config"
)

// Only settings consumed by Samba startup affect an already running daemon.
// In particular, a UI, TLS, LDAP password or backup change must not drop SMB
// sessions. New credentials are still used on any subsequent join attempt.
func sambaSettings(snapshot config.Snapshot, env map[string]string) [10]string {
	phase := snapshot.Phase
	if phase == "groups" {
		phase = "joining"
	}
	return [10]string{
		phase, env["REALM"], env["WORKGROUP"], env["DOMAIN"], env["NETBIOS_NAME"],
		env["AD_DNS_NAME"], env["AD_DNS_IP"], env["DOMAIN_USERS_SID"], env["DOMAIN_ADMINS_SID"], env["FSLOGIX_GROUP_SID"],
	}
}

func serveSamba(ctx context.Context, store *config.Store, options Options) error {
	run := &runner{store: store, options: options}
	if err := run.removeReadiness(); err != nil {
		return err
	}
	defer func() {
		_ = run.removeReadiness()
		run.domain.stop()
		_ = run.removeReadiness()
	}()

	var settings [10]string
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		snapshot, err := store.Snapshot(ctx)
		if err != nil {
			return err
		}
		env, err := store.Environment(snapshot, false)
		if err != nil {
			return err
		}

		desired := sambaSettings(snapshot, env)
		if desired != settings {
			if err := run.removeReadiness(); err != nil {
				return err
			}
			run.domain.stop()
			if err := run.removeReadiness(); err != nil {
				return err
			}
			run.domain = nil
			run.nextDomain = time.Time{}
			settings = desired
		}

		if err := run.domainTick(ctx, snapshot, env, time.Now(), true); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
	return nil
}
