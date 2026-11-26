package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ParseLegacy reads assignments without interpolating variables or executing commands.
func ParseLegacy(text string) (map[string]string, error) {
	values := make(map[string]string)
	for line := range strings.SplitSeq(text, "\n") {
		line = strings.TrimPrefix(strings.TrimSpace(line), "export ")
		name, value, assignment := strings.Cut(line, "=")
		_, known := recognized[name]
		if !assignment || !known {
			continue
		}
		parsed, err := shellWords(value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		values[name] = parsed
	}
	return values, nil
}

// shellWords implements the quoting, escaping and comments used by the old shlex import.
func shellWords(value string) (string, error) {
	var words []string
	var word strings.Builder
	var quote byte
	found := false
	for i := 0; i < len(value); i++ {
		char := value[i]
		if quote == 0 && char == '#' {
			break
		}
		if quote == 0 && strings.ContainsRune(" \t\r\n", rune(char)) {
			if found {
				words = append(words, word.String())
				word.Reset()
				found = false
			}
			continue
		}

		found = true
		switch {
		case quote != 0 && char == quote:
			quote = 0
		case quote == 0 && (char == '\'' || char == '"'):
			quote = char
		case char == '\\' && quote != '\'':
			if i+1 >= len(value) {
				return "", errors.New("unvollständige Escape-Sequenz")
			}
			if quote == '"' && value[i+1] != '"' && value[i+1] != '\\' {
				word.WriteByte(char)
			} else {
				i++
				word.WriteByte(value[i])
			}
		default:
			word.WriteByte(char)
		}
	}
	if quote != 0 {
		return "", errors.New("nicht abgeschlossenes Anführungszeichen")
	}
	if found {
		words = append(words, word.String())
	}
	return strings.Join(words, " "), nil
}

// ImportLegacy upgrades a prior container or .env exactly once without touching its join.
func (store *Store) ImportLegacy(ctx context.Context, values map[string]string) (bool, error) {
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		return false, err
	}
	if snapshot.Phase == "configured" || snapshot.Revision != 0 {
		return false, ErrConflict
	}

	public, private := make(Values), make(Values)
	for name, value := range values {
		if _, ok := publicFields[name]; ok {
			public[name], err = Validate(name, value)
			if err != nil {
				return false, err
			}
		} else if _, ok := recognized[name]; ok {
			if strings.ContainsRune(value, 0) {
				return false, fmt.Errorf("%s: ungültiges Steuerzeichen", name)
			}
			private[name] = value
		}
	}

	if password := private.String("TLS_CA_PROVISIONER_PASSWORD"); password != "" {
		public["TLS_CA_PASSWORD"] = password
		delete(private, "TLS_CA_PROVISIONER_PASSWORD")
	}
	if path := private.String("TLS_CA_PROVISIONER_PASSWORD_FILE"); path != "" {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			password, err := os.ReadFile(path)
			if err != nil {
				return false, fmt.Errorf("CA-Passwortdatei konnte nicht gelesen werden")
			}
			public["TLS_CA_PASSWORD"] = strings.TrimRight(string(password), "\r\n")
			delete(private, "TLS_CA_PROVISIONER_PASSWORD_FILE")
		}
	}
	if public.String("WEB_TLS_MODE") == "" {
		switch {
		case public.String("ACME_CA_SERVER") != "":
			public["WEB_TLS_MODE"] = "acme"
		case public.String("TLS_CA_URL") != "":
			public["WEB_TLS_MODE"] = "ca"
		case private.String("WEB_TLS_CERT_FILE") != "":
			public["WEB_TLS_MODE"] = "files"
		default:
			public["WEB_TLS_MODE"] = "self-signed"
		}
	}
	if !hasSettings(public, "REALM", "WORKGROUP", "DOMAIN", "DOMAIN_USERS_SID", "DOMAIN_ADMINS_SID") {
		return false, nil
	}

	if _, found := public["FSLOGIX_GROUP_SID"]; !found {
		public["FSLOGIX_GROUP_SID"] = public["DOMAIN_USERS_SID"]
	}
	if _, found := public["BACKUP_AUTO_ENABLED"]; !found {
		public["BACKUP_AUTO_ENABLED"] = true
	}
	public["BACKUP_ENCRYPTION_ENABLED"] = false
	for key, value := range public {
		snapshot.Values[key] = value
	}
	for key, value := range private {
		snapshot.Values[key] = value
	}

	if err := store.update(ctx, 0, "configured", snapshot.Values, 1); err != nil {
		return false, err
	}
	_ = os.Remove(filepath.Join(store.root, "setup-code"))
	return true, nil
}

// ImportSetup preserves inline settings and keys. Server-local path overrides
// belong to the operator's CLI import, not an HTTP upload.
func (store *Store) ImportSetup(ctx context.Context, text string) (bool, error) {
	values, err := ParseLegacy(text)
	if err != nil {
		return false, errors.New("Ungültige frühere Konfiguration")
	}
	for name, value := range values {
		if _, public := publicFields[name]; public {
			continue
		}
		switch name {
		case "WEB_JWT_SECRET", "BACKUP_ARCHIVE_PASSWORD", "BACKUP_NAMESPACE", "BACKUP_KEY_ID", "BACKUP_KEY_FORMAT", "TLS_CA_PROVISIONER_PASSWORD":
		default:
			if value != "" {
				return false, errors.New("Serverlokale Einstellungen bitte über import-legacy importieren")
			}
			delete(values, name)
		}
	}
	if values["WEB_TLS_MODE"] == "files" && !hasSettings(Values{
		"WEB_TLS_CERT_PEM": values["WEB_TLS_CERT_PEM"], "WEB_TLS_KEY_PEM": values["WEB_TLS_KEY_PEM"],
	}, "WEB_TLS_CERT_PEM", "WEB_TLS_KEY_PEM") {
		return false, errors.New("HTTPS-Zertifikat und Schlüssel fehlen; bitte über import-legacy importieren")
	}
	return store.ImportLegacy(ctx, values)
}
