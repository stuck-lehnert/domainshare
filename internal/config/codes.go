package config

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// SetupCode loads a code from the shared state or publishes a new private code.
func (store *Store) SetupCode(httpsOnly bool) (string, error) {
	name := "setup-code"
	if httpsOnly {
		name = "https-setup-code"
	}
	path := filepath.Join(store.root, name)

	read := func() (string, error) {
		body, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		code := strings.TrimSpace(string(body))
		if code == "" {
			return "", errors.New("setup code file is empty")
		}
		return code, nil
	}
	if code, err := read(); !errors.Is(err, os.ErrNotExist) {
		return code, err
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	code := base64.RawURLEncoding.EncodeToString(secret)
	temp, err := os.CreateTemp(store.root, ".setup-code-")
	if err != nil {
		return "", err
	}
	defer os.Remove(temp.Name())
	defer temp.Close()
	if _, err := temp.WriteString(code); err != nil {
		return "", err
	}
	if err := temp.Sync(); err != nil {
		return "", err
	}
	if err := temp.Close(); err != nil {
		return "", err
	}

	if err := os.Link(temp.Name(), path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return read()
		}
		return "", err
	}
	return code, nil
}

func (store *Store) MatchesSetupCode(supplied string, httpsOnly bool) (bool, error) {
	if supplied == "" {
		return false, nil
	}
	code, err := store.SetupCode(httpsOnly)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare([]byte(supplied), []byte(code)) == 1, nil
}
