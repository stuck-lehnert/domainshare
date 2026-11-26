// domainshare contains the native Go commands used by the container.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/stuck-lehnert/domainshare/internal/config"
	"github.com/stuck-lehnert/domainshare/internal/documents"
	"github.com/stuck-lehnert/domainshare/internal/health"
)

func run(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: domainshare <healthcheck|export-shell|import-legacy|import-runtime|tls-prepare|http-setup|web|document-index|audit-collector|backup|trash-cleanup|reconcile|supervise>")
	}

	switch args[0] {
	case "healthcheck":
		flags := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
		port := flags.Int("port", health.DefaultPort, "local HTTPS listener port")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() > 0 {
			return fmt.Errorf("healthcheck takes no positional arguments")
		}
		return health.Check(ctx, *port)
	case "export-shell", "import-legacy", "import-runtime":
		flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
		root := flags.String("state-root", config.DefaultRoot, "persistent configuration directory")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() > 0 {
			return fmt.Errorf("%s takes no positional arguments", args[0])
		}
		if args[0] == "export-shell" {
			return exportShell(ctx, *root, stdout)
		}
		return importSettings(ctx, *root, args[0] == "import-runtime", stdin, stdout)
	case "tls-prepare", "ca-download", "http-setup", "web", "document-index", "audit-collector", "backup", "trash-cleanup", "reconcile", "supervise":
		return runService(ctx, args[0], args[1:])
	default:
		return fmt.Errorf("unknown domainshare command %q", args[0])
	}
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "document-extract" {
		os.Exit(documents.RunExtractHelper(os.Args[2]))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stdin, os.Stdout)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
