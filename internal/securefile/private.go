// Package securefile writes state files without exposing incomplete secrets.
package securefile

import (
	"os"
	"path/filepath"
)

// WritePrivate replaces a file atomically with owner-only permissions.
func WritePrivate(path string, data []byte) error {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(parent, ".domainshare-")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	defer temp.Close()

	if _, err := temp.Write(data); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(temp.Name(), path)
}
