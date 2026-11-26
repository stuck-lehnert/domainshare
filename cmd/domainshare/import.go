package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/stuck-lehnert/domainshare/internal/config"
)

func importSettings(ctx context.Context, root string, fromRuntime bool, stdin io.Reader, stdout io.Writer) error {
	store, err := config.Open(ctx, root)
	if err != nil {
		return err
	}
	defer store.Close()

	const limit = 1024 * 1024
	payload, err := io.ReadAll(io.LimitReader(stdin, limit+1))
	if err != nil {
		return err
	}

	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		return err
	}
	if snapshot.Revision != 0 {
		_, err := fmt.Fprintln(stdout, "Persistent configuration already exists; legacy import skipped.")
		return err
	}
	if len(payload) > limit {
		return errors.New("legacy configuration is too large")
	}

	var values map[string]string
	if fromRuntime {
		var items []*string
		if err := json.Unmarshal(payload, &items); err != nil || items == nil {
			return errors.New("invalid container configuration")
		}
		values = make(map[string]string)
		for _, item := range items {
			if item == nil {
				return errors.New("invalid container configuration")
			}
			if key, value, ok := strings.Cut(*item, "="); ok {
				values[key] = value
			}
		}
	} else {
		values, err = config.ParseLegacy(string(payload))
		if err != nil {
			return err
		}
	}

	imported, err := store.ImportLegacy(ctx, values)
	if err != nil {
		return err
	}
	if !imported {
		if fromRuntime {
			_, err := fmt.Fprintln(stdout, "No legacy domain configuration found; continue web setup.")
			return err
		}
		return errors.New("Unvollständige frühere Konfiguration")
	}

	_, err = fmt.Fprintln(stdout, "Imported existing configuration without changing data or the domain join.")
	return err
}
