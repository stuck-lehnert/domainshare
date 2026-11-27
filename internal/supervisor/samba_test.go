package supervisor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stuck-lehnert/domainshare/internal/config"
)

func TestManagementDoesNotOwnSambaReadiness(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"domainshare-domain-ready", "domainshare-services-ready"} {
		if err := os.WriteFile(filepath.Join(root, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	run := &runner{options: Options{Role: "management", RunRoot: root}}
	if err := run.removeReadiness(); err != nil {
		t.Fatal(err)
	}
	if !exists(filepath.Join(root, "domainshare-domain-ready")) || !run.servicesReady(config.Snapshot{Phase: "configured"}) {
		t.Fatal("management cleanup cleared Samba's readiness")
	}

	run.options.Role = "samba"
	if err := run.removeReadiness(); err != nil {
		t.Fatal(err)
	}
	if exists(filepath.Join(root, "domainshare-domain-ready")) || exists(filepath.Join(root, "domainshare-services-ready")) {
		t.Fatal("Samba cleanup left stale readiness")
	}
}

func TestOnlySambaSettingsChangeSMBLifecycle(t *testing.T) {
	snapshot := config.Snapshot{Phase: "configured", ServiceRevision: 1}
	env := map[string]string{"WORKGROUP": "TEST", "FSLOGIX_GROUP_SID": "S-1-5-21-1-513"}
	initial := sambaSettings(snapshot, env)
	snapshot.ServiceRevision++
	env["WEB_HOSTNAME"] = "new.example.test"
	env["WEB_TLS_MODE"] = "acme"
	env["JOIN_PASSWORD"] = "new credential"
	env["BACKUP_DESTINATION"] = "rsync://example.test/backups"
	if sambaSettings(snapshot, env) != initial {
		t.Fatal("management settings would restart SMB")
	}

	env["FSLOGIX_GROUP_SID"] = "S-1-5-21-1-1024"
	if sambaSettings(snapshot, env) == initial {
		t.Fatal("FSLogix access group change was not detected")
	}

	snapshot.Phase = "joining"
	joining := sambaSettings(snapshot, env)
	snapshot.Phase = "groups"
	if sambaSettings(snapshot, env) != joining {
		t.Fatal("entering the group selection screen would restart Winbind")
	}
}

func TestSambaRoleDoesNotRestartOnManagementSettings(t *testing.T) {
	root := t.TempDir()
	store, err := config.Open(t.Context(), filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	imported, err := store.ImportLegacy(t.Context(), map[string]string{
		"REALM": "EXAMPLE.TEST", "WORKGROUP": "EXAMPLE", "DOMAIN": "dc.example.test",
		"DOMAIN_USERS_SID": "S-1-5-21-1-513", "DOMAIN_ADMINS_SID": "S-1-5-21-1-512",
	})
	if err != nil || !imported {
		t.Fatalf("configure fixture: imported=%v, err=%v", imported, err)
	}

	const init = `#!/bin/sh
set -eu
test "$DOMAINSHARE_SAMBA_ONLY" = true
printf '%s\n' "$FSLOGIX_GROUP_SID" >> "$DOMAINSHARE_RUN_ROOT/starts"
touch "$DOMAINSHARE_RUN_ROOT/domainshare-domain-ready" "$DOMAINSHARE_RUN_ROOT/domainshare-services-ready"
exec sleep 30
`
	if err := os.WriteFile(filepath.Join(root, "init.sh"), []byte(init), 0o700); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, store, Options{AppRoot: root, RunRoot: root, Binary: "/unused", Native: true, Role: "samba"})
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	}()

	starts := func() string {
		lines, _ := os.ReadFile(filepath.Join(root, "starts"))
		return string(lines)
	}
	waitForStarts := func(expected string) {
		t.Helper()
		deadline := time.Now().Add(6 * time.Second)
		for time.Now().Before(deadline) {
			if starts() == expected {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatalf("Samba roles launched with %q, want %q", starts(), expected)
	}

	const initial = "S-1-5-21-1-513\n"
	waitForStarts(initial)
	if err := store.Save(t.Context(), config.Values{"WEB_HOSTNAME": "new.example.test"}, 1, false); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1200 * time.Millisecond)
	if starts() != initial {
		t.Fatal("web settings unexpectedly restarted Samba")
	}

	const newGroup = "S-1-5-21-1-1024"
	if err := store.Save(t.Context(), config.Values{"FSLOGIX_GROUP_SID": newGroup}, 2, false); err != nil {
		t.Fatal(err)
	}
	waitForStarts(initial + newGroup + "\n")
}
