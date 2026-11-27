package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/stuck-lehnert/domainshare/internal/config"
	"github.com/stuck-lehnert/domainshare/internal/supervisor"
	"github.com/stuck-lehnert/domainshare/internal/tlssetup"
)

func runService(ctx context.Context, command string, args []string) error {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	root := flags.String("state-root", config.DefaultRoot, "persistent configuration directory")
	var address, assets, app, runtime *string
	var native *bool
	var role *string
	var slot *string
	switch command {
	case "http-setup":
		address = flags.String("listen", "0.0.0.0:80", "HTTP setup listener")
		assets = flags.String("assets", "/app/web", "setup assets directory")
	case "web":
		address = flags.String("listen", "", "override the HTTPS listen address")
		assets = flags.String("assets", "/app/web", "web assets directory")
		runtime = flags.String("run-root", "/run", "runtime marker directory")
	case "supervise":
		app = flags.String("app-root", "/app", "application directory")
		runtime = flags.String("run-root", "/run", "runtime marker directory")
		native = flags.Bool("native", false, "use the Go backend and workers")
		role = flags.String("role", "combined", "container role: combined, management, or samba")
	case "backup":
		slot = flags.String("slot", "", "run at most once for this scheduled UTC hour (YYYY-MM-DDTHH)")
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("%s takes no positional arguments", command)
	}

	store, err := config.Open(ctx, *root)
	if err != nil {
		return err
	}
	defer store.Close()

	switch command {
	case "tls-prepare":
		return tlssetup.Prepare(ctx, store)
	case "ca-download":
		snapshot, err := store.Snapshot(ctx)
		if err != nil {
			return err
		}
		env, err := store.Environment(snapshot, false)
		if err != nil {
			return err
		}
		return tlssetup.DownloadCABundle(ctx, env["ACME_CA_CERTIFICATES_URL"],
			env["ACME_CA_CERTIFICATES"]+".download.tmp", snapshot.Values.Bool("ACME_CA_CERTIFICATES_INSECURE_DOWNLOAD"))
	case "http-setup":
		return serveSetup(ctx, *address, tlssetup.HTTPHandler(store, os.DirFS(*assets)))
	case "web":
		return runWeb(ctx, store, *address, *assets, *runtime)
	case "document-index":
		return runDocumentIndex(ctx, store)
	case "audit-collector":
		return runAuditCollector(ctx, store)
	case "backup":
		return runBackup(ctx, store, *slot)
	case "trash-cleanup":
		return runTrashCleanup(ctx, store)
	case "reconcile":
		return runReconciliation(ctx, store)
	case "supervise":
		self, err := os.Executable()
		if err != nil {
			return err
		}
		return supervisor.Run(ctx, store, supervisor.Options{Binary: self, AppRoot: *app, RunRoot: *runtime, Native: *native, Role: *role})
	default:
		return fmt.Errorf("unknown service %q", command)
	}
}

func serveSetup(ctx context.Context, address string, handler http.Handler) error {
	server := &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       10 * time.Second,
		MaxHeaderBytes:    16 * 1024,
		ErrorLog:          log.New(io.Discard, "", 0), // Never log setup headers or bodies.
	}
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()

	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			return errors.Join(err, server.Close())
		}
		return nil
	}
}
