package config

import (
	"context"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
)

type PublicConfiguration struct {
	Revision   int64            `json:"revision"`
	Phase      string           `json:"phase"`
	Sections   []PublicSection  `json:"sections"`
	Encryption BackupEncryption `json:"encryption"`
}

type PublicSection struct {
	ID     string           `json:"id"`
	Label  string           `json:"label"`
	Fields []map[string]any `json:"fields"`
}

type BackupEncryption struct {
	KeyID  string `json:"keyId"`
	Legacy bool   `json:"legacy"`
}

// Public exposes only public field metadata and values. It never serializes
// Snapshot.Values and never includes stored passwords, private keys or JWT secrets.
func (store *Store) Public(ctx context.Context, section string) (PublicConfiguration, error) {
	snap, err := store.Snapshot(ctx)
	if err != nil {
		return PublicConfiguration{}, err
	}
	return snap.Public(section)
}

// Public renders the same revision that was authorized by the caller.
func (snap Snapshot) Public(section string) (PublicConfiguration, error) {
	var specs struct {
		Fields   []map[string]any `json:"fields"`
		Sections []PublicSection  `json:"sections"`
	}
	// Keep the optional field metadata such as required, choices and bounds.
	if err := json.Unmarshal(schemaJSON, &specs); err != nil {
		return PublicConfiguration{}, err
	}

	keyID := snap.Values.String("BACKUP_KEY_ID")
	result := PublicConfiguration{
		Revision: snap.Revision, Phase: snap.Phase, Sections: make([]PublicSection, 0, len(specs.Sections)),
		Encryption: BackupEncryption{KeyID: keyID, Legacy: keyID == "" && snap.Values.String("BACKUP_ARCHIVE_PASSWORD") != ""},
	}

	for _, group := range specs.Sections {
		if section != "" && group.ID != section {
			continue
		}
		group.Fields = make([]map[string]any, 0)
		for _, spec := range specs.Fields {
			name, ok := spec["key"].(string)
			if !ok || spec["section"] != group.ID || slices.Contains(schema.PrivateFields, name) {
				continue
			}
			value, exists := snap.Values[name]
			if !exists {
				value = spec["default"]
			}
			spec["value"], spec["configured"] = value, false
			switch spec["kind"] {
			case "secret", "secretpem", "secreturl":
				secret, _ := value.(string)
				spec["value"], spec["configured"] = "", secret != ""
				if spec["kind"] == "secreturl" && secret != "" {
					spec["summary"] = destinationSummary(secret)
				}
			}
			group.Fields = append(group.Fields, spec)
		}
		result.Sections = append(result.Sections, group)
	}
	return result, nil
}

func destinationSummary(secret string) string {
	parsed, err := url.Parse(secret)
	if err != nil || parsed.Hostname() == "" {
		return ""
	}
	// Redact userinfo, query options and fragments, not merely the password.
	return (&url.URL{
		Scheme: parsed.Scheme, Host: strings.ToLower(parsed.Host), Path: parsed.Path, RawPath: parsed.RawPath,
	}).String()
}

func FieldSection(name string) string { return publicFields[name].Section }
