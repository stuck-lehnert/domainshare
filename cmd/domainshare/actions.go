package main

import (
	"context"
	"errors"
	"log"
	"sync"

	"github.com/stuck-lehnert/domainshare/internal/accesscontrol"
	"github.com/stuck-lehnert/domainshare/internal/backup"
	"github.com/stuck-lehnert/domainshare/internal/config"
)

type adminActions struct {
	ctx   context.Context
	store *config.Store

	mu      sync.Mutex
	workers sync.WaitGroup
	stopped bool
	running map[string]bool
}

func (actions *adminActions) stop() {
	actions.mu.Lock()
	actions.stopped = true
	actions.mu.Unlock()
	actions.workers.Wait()
}

func (actions *adminActions) start(request context.Context, action string) error {
	if action != "backup" && action != "reconciliation" {
		return errors.New("unknown admin action")
	}

	actions.mu.Lock()
	if actions.stopped || actions.ctx.Err() != nil || request.Err() != nil {
		actions.mu.Unlock()
		return context.Canceled
	}
	if actions.running[action] {
		actions.mu.Unlock()
		return accesscontrol.Conflict("Die Aktion läuft bereits")
	}
	actions.running[action] = true
	actions.workers.Add(1)
	actions.mu.Unlock()

	// The request waits only until the worker acquires its cross-process lock.
	// Once accepted, the worker belongs to the server, not the client request.
	result := make(chan error, 1)
	go func() {
		defer actions.workers.Done()
		started := false
		reportStarted := func() {
			started = true
			result <- nil
		}

		var err error
		switch action {
		case "backup":
			err = actions.backup(reportStarted)
		case "reconciliation":
			err = reconcileShares(actions.ctx, actions.store, "web", reportStarted)
		}

		actions.mu.Lock()
		delete(actions.running, action)
		actions.mu.Unlock()
		if !started {
			result <- err
		} else if err != nil {
			log.Printf("[web] background %s did not complete; see worker status", action)
		}
	}()

	select {
	case err := <-result:
		return err
	case <-request.Done():
		return request.Err()
	case <-actions.ctx.Done():
		return actions.ctx.Err()
	}
}

func (actions *adminActions) backup(started func()) error {
	err := backup.RunConfigured(actions.ctx, actions.store.Root(), func() (backup.Options, error) {
		_, env, err := configuredEnv(actions.ctx, actions.store)
		if err != nil {
			return backup.Options{}, err
		}

		options := backupOptions(env, "web")
		if options.Destination == "" {
			return options, accesscontrol.Conflict("Es ist kein Sicherungsziel eingerichtet")
		}
		if options.Encrypted && options.Password == "" {
			return options, accesscontrol.Conflict("Es ist kein Sicherungsschlüssel eingerichtet")
		}

		started()
		return options, nil
	})
	if errors.Is(err, backup.ErrBusy) {
		return accesscontrol.Conflict("Eine Sicherung läuft bereits")
	}
	return err
}
