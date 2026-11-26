package config

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
)

func hasSettings(values Values, keys ...string) bool {
	for _, key := range keys {
		if values.String(key) == "" {
			return false
		}
	}
	return true
}

func (store *Store) update(ctx context.Context, revision int64, phase string, values Values, services int) error {
	encoded, err := json.Marshal(values)
	if err != nil {
		return err
	}

	result, err := store.db.ExecContext(ctx, `UPDATE configuration SET settings=?, phase=?,
		revision=revision+1, service_revision=service_revision+? WHERE id=1 AND revision=?`,
		string(encoded), phase, services, revision)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrConflict
	}
	return nil
}

// Save applies validated public settings with an optimistic revision check.
// The bootstrap flag may only be used by authenticated setup handlers.
func (store *Store) Save(ctx context.Context, changes Values, revision int64, bootstrap bool) error {
	return store.save(ctx, changes, revision, bootstrap, "")
}

// SubmitDomain publishes settings and invalidates the previous join in one revision.
func (store *Store) SubmitDomain(ctx context.Context, changes Values, revision int64) error {
	for name := range changes {
		switch FieldSection(name) {
		case "domain", "network", "tls":
		default:
			return errors.New("Nur Domänen-, Server- und HTTPS-Einstellungen sind hier zulässig")
		}
	}

	return store.save(ctx, changes, revision, true, "joining")
}

// CompleteSetup commits the validated groups and closes setup atomically.
// The caller must verify group membership against the AD for this revision.
func (store *Store) CompleteSetup(ctx context.Context, changes Values, revision int64) error {
	if len(changes) != 3 || !hasSettings(changes, "DOMAIN_USERS_SID", "DOMAIN_ADMINS_SID", "FSLOGIX_GROUP_SID") {
		return errors.New("Benutzer-, Administratoren- und FSLogix-Gruppe auswählen")
	}

	return store.save(ctx, changes, revision, true, "configured")
}

func (store *Store) save(ctx context.Context, changes Values, revision int64, bootstrap bool, nextPhase string) error {
	normalized := make(Values, len(changes))
	for name, value := range changes {
		parsed, err := Validate(name, value)
		if err != nil {
			return err
		}
		normalized[name] = parsed
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		return err
	}
	if revision != snapshot.Revision || (bootstrap && snapshot.Phase == "configured") {
		return ErrConflict
	}
	if nextPhase == "configured" && snapshot.Phase != "groups" {
		return ErrConflict
	}

	values := make(Values, len(snapshot.Values))
	for name, value := range snapshot.Values {
		values[name] = value
	}
	serviceChange := 0
	for name, value := range normalized {
		if reflect.DeepEqual(values[name], value) {
			continue
		}
		if !bootstrap && (name == "REALM" || name == "WORKGROUP") {
			return errors.New("Ein Wechsel der AD-Domäne erfordert einen erneuten Domänenbeitritt")
		}
		values[name] = value
		section := publicFields[name].Section
		if section != "backup" && !(bootstrap && section == "groups") {
			serviceChange = 1
		}
	}

	if values.String("WEB_TLS_MODE") == "files" {
		inline := hasSettings(values, "WEB_TLS_CERT_PEM", "WEB_TLS_KEY_PEM")
		files := hasSettings(values, "WEB_TLS_CERT_FILE", "WEB_TLS_KEY_FILE")
		if (!inline && !files) || (!inline && (values.String("WEB_TLS_CERT_PEM") != "" || values.String("WEB_TLS_KEY_PEM") != "")) {
			return errors.New("Bitte HTTPS-Zertifikat und privaten Schlüssel gemeinsam hochladen")
		}
		if inline {
			_, err := tls.X509KeyPair([]byte(values.String("WEB_TLS_CERT_PEM")), []byte(values.String("WEB_TLS_KEY_PEM")))
			if err != nil {
				return errors.New("HTTPS-Zertifikat und privater Schlüssel sind ungültig oder passen nicht zusammen")
			}
		}
	}
	if keyID := values.String("BACKUP_KEY_ID"); keyID != "" {
		if _, changed := normalized["BACKUP_ENCRYPTION_ENABLED"]; changed {
			values["BACKUP_NAMESPACE"] = "plain"
			if values.Bool("BACKUP_ENCRYPTION_ENABLED") {
				values["BACKUP_NAMESPACE"] = "keys/" + keyID
			}
		}
	} else if values.Bool("BACKUP_ENCRYPTION_ENABLED") && values.String("BACKUP_DESTINATION") != "" {
		return errors.New("Bitte zuerst eine Wiederherstellungsphrase erzeugen und bestätigen")
	}

	phase := snapshot.Phase
	switch nextPhase {
	case "joining":
		if !hasSettings(values, "REALM", "WORKGROUP", "DOMAIN", "JOIN_USER", "JOIN_PASSWORD") {
			return errors.New("Domäne und Zugangsdaten für den Beitritt sind erforderlich")
		}
		phase, serviceChange = nextPhase, 1
	case "configured":
		if !hasSettings(values, "REALM", "WORKGROUP", "DOMAIN", "DOMAIN_USERS_SID", "DOMAIN_ADMINS_SID", "FSLOGIX_GROUP_SID") {
			return errors.New("Domäne und Gruppen müssen vollständig eingerichtet sein")
		}
		phase, serviceChange = nextPhase, 1
	}

	if serviceChange == 0 && reflect.DeepEqual(values, snapshot.Values) {
		return nil
	}
	if err := store.update(ctx, revision, phase, values, serviceChange); err != nil {
		return err
	}

	if nextPhase == "configured" {
		// The committed phase already disables the code, even if unlink fails.
		_ = os.Remove(filepath.Join(store.root, "setup-code"))
	}
	return nil
}
