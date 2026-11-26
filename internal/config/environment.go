package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/stuck-lehnert/domainshare/internal/securefile"
)

func fieldsSet() map[string]struct{} {
	keys := make(map[string]struct{}, len(schema.Fields)+len(schema.PrivateFields))
	for _, item := range schema.Fields {
		keys[item.Key] = struct{}{}
	}
	for _, key := range schema.PrivateFields {
		keys[key] = struct{}{}
	}
	return keys
}

var recognized = fieldsSet()

func envValue(value any) (string, error) {
	switch value := value.(type) {
	case string:
		return value, nil
	case bool:
		return strconv.FormatBool(value), nil
	case json.Number:
		return value.String(), nil
	case int:
		return strconv.Itoa(value), nil
	default:
		return "", fmt.Errorf("unsupported configuration value type %T", value)
	}
}

// Environment projects one snapshot into the subprocess environment. The
// materialize flag is used only by the launcher, not by ordinary reads.
func (store *Store) Environment(snapshot Snapshot, materialize bool) (map[string]string, error) {
	result := make(map[string]string, len(snapshot.Values))
	for name, value := range snapshot.Values {
		if _, ok := recognized[name]; !ok {
			continue
		}
		text, err := envValue(value)
		if err != nil {
			return nil, fmt.Errorf("setting %s: %w", name, err)
		}
		if strings.ContainsRune(text, '\x00') {
			return nil, fmt.Errorf("setting %s contains a null byte", name)
		}
		result[name] = text
	}

	for _, key := range []string{"LDAP_URI", "LDAP_BASE_DN", "AD_DNS_NAME"} {
		if result[key] == "" {
			delete(result, key)
		}
	}
	if realm := strings.ToLower(result["REALM"]); realm != "" {
		if result["LDAP_BASE_DN"] == "" {
			result["LDAP_BASE_DN"] = "DC=" + strings.ReplaceAll(realm, ".", ",DC=")
		}
		if result["AD_DNS_NAME"] == "" {
			hostname, ok := result["SAMBA_HOSTNAME"]
			if !ok {
				hostname = "domainshare"
			}
			hostname = strings.ToLower(hostname)
			if !strings.Contains(hostname, ".") {
				hostname += "." + realm
			}
			result["AD_DNS_NAME"] = hostname
		}
	}

	tlsDir := filepath.Join(store.root, "tls")
	defaults := map[string]string{
		"STATE_DB_PATH":     filepath.Join(store.root, "shares.db"),
		"WEB_TLS_CERT_FILE": filepath.Join(tlsDir, "web.crt"),
		"WEB_TLS_KEY_FILE":  filepath.Join(tlsDir, "web.key"),
		"WEB_BIND_PORT":     "8443",
		"WEB_HTTPS_PORT":    "443",
	}
	for key, value := range defaults {
		if _, ok := result[key]; !ok {
			result[key] = value
		}
	}
	result["WEB_ENABLED"] = "true"
	result["STATE_ROOT"] = store.root
	result["ACME_HTTP_LISTEN"] = "127.0.0.1:8080"
	if result["ACME_CA_CERTIFICATES"] == "" {
		if result["ACME_CA_CERTIFICATES_PEM"] != "" || result["ACME_CA_CERTIFICATES_URL"] != "" {
			result["ACME_CA_CERTIFICATES"] = filepath.Join(tlsDir, "acme-ca-certificates.pem")
		} else {
			result["ACME_CA_CERTIFICATES"] = "/etc/ssl/certs/ca-certificates.crt"
		}
	}

	for _, secret := range []struct{ setting, file, export string }{
		{"ACME_CA_CERTIFICATES_PEM", "acme-ca-certificates.pem", "ACME_CA_CERTIFICATES"},
		{"TLS_CA_ROOT_PEM", "ca-root.pem", "TLS_CA_ROOT"},
		{"TLS_CA_PASSWORD", "ca-password", "TLS_CA_PROVISIONER_PASSWORD_FILE"},
	} {
		path := filepath.Join(tlsDir, secret.file)
		value := result[secret.setting]
		if value == "" {
			if materialize && secret.setting == "TLS_CA_PASSWORD" {
				if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
					return nil, err
				}
			}
			continue
		}

		if materialize {
			if old, err := os.ReadFile(path); err != nil || string(old) != value {
				if err := securefile.WritePrivate(path, []byte(value)); err != nil {
					return nil, err
				}
			}
		}
		result[secret.export] = path
		if secret.setting == "TLS_CA_ROOT_PEM" && result["TLS_CA_FINGERPRINT"] == "" {
			block, _ := pem.Decode([]byte(value))
			if block == nil || block.Type != "CERTIFICATE" {
				return nil, fmt.Errorf("TLS_CA_ROOT_PEM is not a PEM certificate")
			}
			hash := sha256.Sum256(block.Bytes)
			result["TLS_CA_FINGERPRINT"] = hex.EncodeToString(hash[:])
		}
	}
	return result, nil
}

// EnvironmentList filters inherited settings before starting a service.
func EnvironmentList(inherited []string, configured, extra map[string]string) []string {
	result := make(map[string]string, len(inherited)+len(configured)+len(extra))
	for _, variable := range inherited {
		key, value, ok := strings.Cut(variable, "=")
		if !ok {
			continue
		}
		if _, isSetting := recognized[key]; !isSetting {
			result[key] = value
		}
	}
	for key, value := range configured {
		result[key] = value
	}
	for key, value := range extra {
		result[key] = value
	}

	variables := make([]string, 0, len(result))
	for key, value := range result {
		variables = append(variables, key+"="+value)
	}
	sort.Strings(variables)
	return variables
}
