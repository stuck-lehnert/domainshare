package main

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/stuck-lehnert/domainshare/internal/config"
)

func exportShell(ctx context.Context, root string, stdout io.Writer) error {
	store, err := config.Open(ctx, root)
	if err != nil {
		return err
	}
	defer store.Close()

	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		return err
	}
	environment, err := store.Environment(snapshot, true)
	if err != nil {
		return err
	}

	keys := make([]string, 0, len(environment))
	for key := range environment {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		quoted := "'" + strings.ReplaceAll(environment[key], "'", `'"'"'`) + "'"
		if _, err := fmt.Fprintf(stdout, "export %s=%s\n", key, quoted); err != nil {
			return err
		}
	}
	return nil
}
