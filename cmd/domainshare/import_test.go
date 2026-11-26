package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stuck-lehnert/domainshare/internal/config"
)

func TestSetupImportsContainerSettingsOnce(t *testing.T) {
	root := t.TempDir()
	const password = "  $literal='value'  "
	legacy, err := json.Marshal([]string{
		"REALM=EXAMPLE.TEST",
		"WORKGROUP=EXAMPLE",
		"DOMAIN=dc.example.test",
		"DOMAIN_USERS_SID=S-1-5-21-1-513",
		"DOMAIN_ADMINS_SID=S-1-5-21-1-512",
		"JOIN_PASSWORD=" + password,
		"BACKUP_ARCHIVE_PASSWORD=legacy-archive-password",
	})
	if err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := run(t.Context(), []string{"import-runtime", "--state-root", root}, bytes.NewReader(legacy), &output); err != nil {
		t.Fatal(err)
	}
	if err := run(t.Context(), []string{"import-legacy", "--state-root", root}, strings.NewReader("REALM=OTHER.TEST\n"), &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "legacy import skipped") || strings.Contains(output.String(), password) {
		t.Fatal("setup must report the skipped import without exposing credentials")
	}

	store, err := config.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	snapshot, err := store.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Phase != "configured" || snapshot.Revision != 1 || snapshot.Values.String("REALM") != "EXAMPLE.TEST" {
		t.Fatal("legacy import did not preserve the original configuration")
	}
	if snapshot.Values.String("JOIN_PASSWORD") != password || snapshot.Values.String("BACKUP_ARCHIVE_PASSWORD") != "legacy-archive-password" {
		t.Fatal("legacy import did not preserve the stored passwords byte for byte")
	}
}
