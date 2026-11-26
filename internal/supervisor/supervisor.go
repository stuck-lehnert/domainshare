// Package supervisor coordinates container setup, TLS, AD and scheduled jobs.
package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/stuck-lehnert/domainshare/internal/config"
	"github.com/stuck-lehnert/domainshare/internal/securefile"
	"github.com/stuck-lehnert/domainshare/internal/tlssetup"
)

type Options struct {
	AppRoot string
	RunRoot string
	Binary  string
	Native  bool
}

type runner struct {
	store               *config.Store
	options             Options
	ui, domain, http    *process
	backup, certificate *process
	audit, index        *process
	reconcile, trash    *process
	revision            int64
	nextDomain, nextTLS time.Time
	lastServiceStatus   string
	backupAttempt       string
	lastReconcile       string
	lastTrash           string
}

func Run(ctx context.Context, store *config.Store, options Options) error {
	if options.AppRoot == "" {
		options.AppRoot = "/app"
	}
	if options.RunRoot == "" {
		options.RunRoot = "/run"
	}
	if options.Binary == "" {
		return errors.New("missing supervisor executable")
	}

	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		return err
	}
	if snapshot.Revision == 0 {
		environment := make(map[string]string)
		for _, item := range os.Environ() {
			if key, value, ok := strings.Cut(item, "="); ok {
				environment[key] = value
			}
		}
		if _, err := store.ImportLegacy(ctx, environment); err != nil && !errors.Is(err, config.ErrConflict) {
			return err
		}

		snapshot, err = store.Snapshot(ctx)
		if err != nil {
			return err
		}
	}
	if snapshot.Phase != "configured" {
		httpsCode, err := store.SetupCode(true)
		if err != nil {
			return err
		}
		setupCode, err := store.SetupCode(false)
		if err != nil {
			return err
		}
		fmt.Println("[setup] Open http://<server>/ for HTTPS only. HTTPS setup code: " + httpsCode)
		fmt.Println("[setup] Open https://<server>/ and enter setup code: " + setupCode)
	}
	if err := tlssetup.Prepare(ctx, store); err != nil {
		return fmt.Errorf("prepare bootstrap HTTPS certificate: %w", err)
	}

	run := &runner{store: store, options: options, revision: -1}
	defer func() {
		_ = run.removeReadiness()
		for _, child := range []*process{run.ui, run.audit, run.index, run.reconcile, run.trash, run.domain, run.backup, run.certificate, run.http} {
			child.stop()
		}
		_ = run.removeReadiness()
	}()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		if err := run.tick(ctx, time.Now()); err != nil && ctx.Err() == nil {
			return err
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
	return nil
}

func (run *runner) tick(ctx context.Context, now time.Time) error {
	snapshot, err := run.store.Snapshot(ctx)
	if err != nil {
		return err
	}
	if snapshot.ServiceRevision != run.revision {
		if err := run.restartServices(ctx, snapshot.ServiceRevision); err != nil {
			return err
		}
	}

	environment, err := run.store.Environment(snapshot, true)
	if err != nil {
		return err
	}
	if run.ui == nil || run.ui.exited() {
		run.ui.stop()
		command := run.pythonService("web_ui.py")
		if run.options.Native {
			command = run.nativeService("web", "--assets", filepath.Join(run.options.AppRoot, "web"), "--run-root", run.options.RunRoot)
		}
		run.ui, err = run.launch(environment, nil, command...)
		if err != nil {
			return err
		}
	}
	if run.http == nil || run.http.exited() {
		run.http.stop()
		run.http, err = run.launch(environment, nil, run.options.Binary, "http-setup",
			"--state-root", run.store.Root(), "--assets", filepath.Join(run.options.AppRoot, "web"))
		if err != nil {
			return err
		}
	}

	tlsReady, err := run.tls(ctx, snapshot, environment, now)
	if err != nil {
		return err
	}
	if err := run.domainTick(ctx, snapshot, environment, now, tlsReady); err != nil {
		return err
	}
	if run.options.Native {
		if !run.servicesReady(snapshot) {
			return nil
		}
		if err := run.nativeWorkers(environment, now.UTC()); err != nil {
			return err
		}
	}
	return run.backupTick(ctx, snapshot, environment, now.UTC())
}

func (run *runner) restartServices(ctx context.Context, revision int64) error {
	if err := run.removeReadiness(); err != nil {
		return err
	}

	for _, child := range []*process{run.ui, run.audit, run.index, run.reconcile, run.trash, run.domain, run.certificate} {
		child.stop()
	}
	run.domain, run.certificate, run.ui = nil, nil, nil
	run.audit, run.index, run.reconcile, run.trash = nil, nil, nil, nil
	if err := run.removeReadiness(); err != nil {
		return err
	}

	run.revision = revision
	run.nextDomain, run.nextTLS = time.Time{}, time.Time{}
	if err := tlssetup.Prepare(ctx, run.store); err != nil {
		return run.serviceStatus("failed", "HTTPS-Zertifikat konnte nicht eingerichtet werden")
	}
	return nil
}

func (run *runner) tls(ctx context.Context, snapshot config.Snapshot, environment map[string]string, now time.Time) (bool, error) {
	if run.certificate.exited() {
		success := run.certificate.exitCode() == 0
		run.certificate.stop()
		run.certificate = nil
		status := tlssetup.Status{State: "ready", Message: "HTTPS ist eingerichtet. Über HTTPS fortfahren."}
		if !success {
			status = tlssetup.Status{State: "failed", Message: "ACME-Zertifikat konnte nicht angefordert werden. Hostname, CA und Erreichbarkeit von Port 80 prüfen."}
		}
		if err := tlssetup.WriteStatus(run.store.Root(), status); err != nil {
			return false, err
		}
	}

	wantsACME := snapshot.Values.String("WEB_TLS_MODE") == "acme" && snapshot.Values.String("ACME_CA_SERVER") != ""
	marker := tlssetup.BootstrapMarker(environment["WEB_TLS_CERT_FILE"])
	pending := wantsACME && exists(marker)
	if pending && run.certificate == nil && !now.Before(run.nextTLS) && ctx.Err() == nil {
		if err := tlssetup.WriteStatus(run.store.Root(), tlssetup.Status{State: "working", Message: "ACME-Zertifikat wird angefordert"}); err != nil {
			return false, err
		}
		run.nextTLS = now.Add(time.Minute)
		child, err := run.launchInit(environment, "--configure-tls")
		if err != nil {
			return false, err
		}
		run.certificate = child
	}
	return !wantsACME || (!pending && run.certificate == nil), nil
}

func (run *runner) domainTick(ctx context.Context, snapshot config.Snapshot, environment map[string]string, now time.Time, tlsReady bool) error {
	if run.domain.exited() {
		code := run.domain.exitCode()
		run.domain.stop()
		run.domain = nil
		if err := run.removeReadiness(); err != nil {
			return err
		}
		for _, child := range []*process{run.audit, run.index, run.reconcile, run.trash} {
			child.stop()
		}
		run.audit, run.index, run.reconcile, run.trash = nil, nil, nil, nil
		run.nextDomain = now.Add(30 * time.Second)
		message := fmt.Sprintf("AD-Dienste konnten nicht gestartet werden (Status %d); Einstellungen prüfen", code)
		return run.serviceStatus("failed", message)
	}
	if run.domain != nil && exists(filepath.Join(run.options.RunRoot, "domainshare-domain-ready")) {
		if snapshot.Phase == "joining" {
			if err := run.store.AdvanceToGroups(ctx, snapshot.Revision); err != nil && !errors.Is(err, config.ErrConflict) {
				return err
			}
		}
		if snapshot.Phase != "configured" || run.servicesReady(snapshot) {
			return run.serviceStatus("running", "Domänenverbindung hergestellt")
		}
		return nil
	}

	desired := snapshot.Phase == "joining" || snapshot.Phase == "groups" || snapshot.Phase == "configured"
	desired = desired && snapshot.Values.String("REALM") != "" && snapshot.Values.String("WORKGROUP") != "" && snapshot.Values.String("DOMAIN") != ""
	if !desired || !tlsReady || run.domain != nil || now.Before(run.nextDomain) || ctx.Err() != nil {
		return nil
	}
	if err := run.serviceStatus("starting", "AD-Dienste werden gestartet"); err != nil {
		return err
	}

	var args []string
	if snapshot.Phase != "configured" {
		args = append(args, "--bootstrap-domain")
	}
	run.nextDomain = now.Add(30 * time.Second)
	child, err := run.launchInit(environment, args...)
	if err != nil {
		return err
	}
	run.domain = child
	return nil
}

func (run *runner) backupTick(ctx context.Context, snapshot config.Snapshot, environment map[string]string, now time.Time) error {
	if run.backup.exited() {
		run.backup.stop()
		run.backup = nil
	}
	if !backupDue(snapshot, now.Hour()) || run.backup != nil || ctx.Err() != nil {
		return nil
	}

	slot := now.Format("2006-01-02T15")
	if run.options.Native {
		if run.backupAttempt == slot {
			return nil
		}
		child, err := run.launch(environment, nil, run.nativeService("backup", "--slot", slot)...)
		if err != nil {
			return fmt.Errorf("launch scheduled backup: %w", err)
		}
		run.backupAttempt, run.backup = slot, child
		return nil
	}

	claimed, err := run.store.ClaimBackupSlot(ctx, slot)
	if err != nil || !claimed {
		return err
	}
	child, err := run.launch(environment, map[string]string{"BACKUP_TRIGGER": "automatic"}, run.pythonService("backup_to_destination.py")...)
	if err != nil {
		log.Print("Scheduled backup could not start")
		return nil
	}
	run.backup = child
	return nil
}

func backupDue(snapshot config.Snapshot, hour int) bool {
	return snapshot.Phase == "configured" && snapshot.Values.String("BACKUP_DESTINATION") != "" &&
		snapshot.Values.Bool("BACKUP_AUTO_ENABLED") && snapshot.Values.Int("BACKUP_START_HOUR") == hour
}

func (run *runner) pythonService(name string) []string {
	// Temporary: remove each call site when its native service meets parity.
	return []string{"python3", filepath.Join(run.options.AppRoot, name)}
}

func (run *runner) launchInit(environment map[string]string, args ...string) (*process, error) {
	command := append([]string{filepath.Join(run.options.AppRoot, "init.sh")}, args...)
	return run.launch(environment, map[string]string{
		"DOMAINSHARE_SUPERVISED": "true", "DOMAINSHARE_NATIVE": fmt.Sprint(run.options.Native),
		"DOMAINSHARE_RUN_ROOT": run.options.RunRoot, "DOMAINSHARE_BINARY": run.options.Binary,
	}, command...)
}

func (run *runner) removeReadiness() error {
	return errors.Join(run.removeMarker("domainshare-services-ready"), run.removeMarker("domainshare-domain-ready"))
}

func (run *runner) launch(environment, extra map[string]string, command ...string) (*process, error) {
	return start(config.EnvironmentList(os.Environ(), environment, extra), command)
}

func (run *runner) serviceStatus(state, message string) error {
	payload, err := json.Marshal(tlssetup.Status{State: state, Message: message})
	if err != nil {
		return err
	}
	if run.lastServiceStatus == string(payload) {
		return nil
	}
	if err := securefile.WritePrivate(filepath.Join(run.store.Root(), "services-status.json"), payload); err != nil {
		return err
	}
	run.lastServiceStatus = string(payload)
	return nil
}

func (run *runner) removeMarker(name string) error {
	err := os.Remove(filepath.Join(run.options.RunRoot, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
