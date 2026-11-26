// domainshare-trash is the one-shot Samba recycle-bin retention worker.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/stuck-lehnert/domainshare/internal/trash"
)

func main() {
	cleanup := flag.Bool("cleanup", false, "remove expired or excluded items from the configured recycle bins")
	flag.Parse()
	if !*cleanup || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: domainshare-trash --cleanup")
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	service, err := trash.New(trash.OptionsFromEnv(os.LookupEnv))
	if err == nil {
		var result trash.CleanupResult
		result, err = service.Cleanup(ctx, time.Time{})
		if err == nil {
			fmt.Printf("[trash] Removed %d expired or excluded item(s) (%d bytes)\n", result.Removed, result.RemovedBytes)
			return
		}
	}
	fmt.Fprintf(os.Stderr, "[trash] %v\n", err)
	os.Exit(1)
}
