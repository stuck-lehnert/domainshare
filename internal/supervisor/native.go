package supervisor

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/stuck-lehnert/domainshare/internal/config"
)

func (run *runner) nativeService(name string, args ...string) []string {
	return append([]string{run.options.Binary, name, "--state-root", run.store.Root()}, args...)
}

func (run *runner) servicesReady(snapshot config.Snapshot) bool {
	if snapshot.Phase != "configured" || (run.options.Role != "management" && (run.domain == nil || run.domain.exited())) {
		return false
	}
	return exists(filepath.Join(run.options.RunRoot, "domainshare-services-ready"))
}

func (run *runner) stopWorkers() {
	for _, child := range []*process{run.audit, run.index, run.reconcile, run.trash} {
		child.stop()
	}
	run.audit, run.index, run.reconcile, run.trash = nil, nil, nil, nil
}

func (run *runner) nativeWorkers(env map[string]string, now time.Time) error {
	for _, worker := range []struct {
		name  string
		child **process
	}{{"audit-collector", &run.audit}, {"document-index", &run.index}} {
		if *worker.child != nil && !(*worker.child).exited() {
			continue
		}
		(*worker.child).stop()
		child, err := run.launch(env, nil, run.nativeService(worker.name)...)
		if err != nil {
			return fmt.Errorf("launch %s: %w", worker.name, err)
		}
		*worker.child = child
	}

	minute := now.Format("2006-01-02T15:04")
	if now.Minute()%5 == 0 && run.lastReconcile != minute && (run.reconcile == nil || run.reconcile.exited()) {
		run.reconcile.stop()
		child, err := run.launch(env, map[string]string{"RECONCILE_TRIGGER": "automatic"}, run.nativeService("reconcile")...)
		if err != nil {
			return fmt.Errorf("launch periodic reconciliation: %w", err)
		}
		run.lastReconcile, run.reconcile = minute, child
	}
	if now.Minute() == 17 && run.lastTrash != minute && (run.trash == nil || run.trash.exited()) {
		run.trash.stop()
		child, err := run.launch(env, nil, run.nativeService("trash-cleanup")...)
		if err != nil {
			return fmt.Errorf("launch periodic trash cleanup: %w", err)
		}
		run.lastTrash, run.trash = minute, child
	}
	return nil
}
