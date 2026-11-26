package webapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"slices"

	"github.com/stuck-lehnert/domainshare/internal/accesscontrol"
	"github.com/stuck-lehnert/domainshare/internal/backup"
	"github.com/stuck-lehnert/domainshare/internal/config"
	"github.com/stuck-lehnert/domainshare/internal/directory"
	"github.com/stuck-lehnert/domainshare/internal/trash"
	"github.com/stuck-lehnert/domainshare/internal/webauth"
)

func readValues(w http.ResponseWriter, r *http.Request, limit int64) (map[string]any, bool) {
	fields, ok := readBoundedObject(w, r, limit)
	if !ok {
		return nil, false
	}
	result := make(map[string]any, len(fields))
	for key, raw := range fields {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			writeError(w, http.StatusBadRequest, "Ungültiges JSON")
			return nil, false
		}
		result[key] = value
	}
	return result, true
}

func (api AdminAPI) settingsWrite(w http.ResponseWriter, r *http.Request, path string, user webauth.Session) {
	body, ok := readBoundedObject(w, r, 256*1024)
	if !ok {
		return
	}

	lock, err := backup.AcquireLock(api.Config.Root())
	if errors.Is(err, backup.ErrBusy) {
		writeError(w, http.StatusConflict, "Während einer Sicherung können Einstellungen und Schlüssel nicht geändert werden")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Sicherungssperre ist nicht verfügbar")
		return
	}
	defer lock.Close()

	ctx := r.Context()
	switch path {
	case "settings":
		api.saveSettings(w, r, body, user)
	case "settings/backup-key/generate":
		key, err := api.Config.GenerateKey(ctx, user.ID)
		adminResult(w, key, err)
	case "settings/backup-key/activate":
		var nonce string
		var writtenDown, acknowledgeOld bool
		if json.Unmarshal(body["nonce"], &nonce) != nil || json.Unmarshal(body["writtenDown"], &writtenDown) != nil || !writtenDown {
			writeError(w, http.StatusBadRequest, "Bitte bestätigen, dass die Phrase sicher notiert wurde")
			return
		}
		if raw, ok := body["acknowledgeOldBackups"]; ok && json.Unmarshal(raw, &acknowledgeOld) != nil {
			writeError(w, http.StatusBadRequest, "Ungültige Bestätigung")
			return
		}
		if err := api.Config.ActivateKey(ctx, user.ID, nonce, writtenDown, acknowledgeOld); err != nil {
			adminResult(w, nil, err)
			return
		}
		result, err := api.Config.Public(ctx, "")
		adminResult(w, result, err)
	}
}

func (api AdminAPI) saveSettings(w http.ResponseWriter, r *http.Request, body map[string]json.RawMessage, user webauth.Session) {
	var revision *int64
	if json.Unmarshal(body["revision"], &revision) != nil || revision == nil {
		writeError(w, http.StatusConflict, "Einstellungen wurden inzwischen geändert")
		return
	}
	var changes config.Values
	decoder := json.NewDecoder(bytes.NewReader(body["values"]))
	decoder.UseNumber()
	if decoder.Decode(&changes) != nil || changes == nil {
		writeError(w, http.StatusBadRequest, "Einstellungen müssen als Objekt angegeben werden")
		return
	}

	ctx := r.Context()
	var changedGroups []string
	restart := false
	for name, value := range changes {
		if _, err := config.Validate(name, value); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		section := config.FieldSection(name)
		restart = restart || section != "backup"
		if section == "groups" {
			changedGroups = append(changedGroups, name)
		}
	}
	if len(changedGroups) > 0 {
		groups, err := api.Directory.ListGroups(ctx)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "Gruppen sind nicht verfügbar")
			return
		}
		for _, name := range changedGroups {
			sid := changes.String(name)
			if !slices.ContainsFunc(groups, func(group directory.Group) bool { return group.SID == sid }) {
				writeError(w, http.StatusBadRequest, "Ausgewählte Gruppe ist nicht im aktuellen AD vorhanden")
				return
			}
		}
		if sid := changes.String("DOMAIN_ADMINS_SID"); sid != "" {
			identity, err := api.Directory.CurrentIdentityWithAdminSID(ctx, user.SID, sid)
			if err != nil || identity.SID != user.SID || !identity.Admin() {
				writeError(w, http.StatusBadRequest, "Sie müssen Mitglied der ausgewählten Administratorengruppe sein")
				return
			}
		}
	}
	if err := api.Config.Save(ctx, changes, *revision, false); err != nil {
		adminResult(w, nil, err)
		return
	}
	if changes.String("DOMAIN_ADMINS_SID") != "" {
		if err := api.Auth.Sessions.RecheckAll(ctx); err != nil {
			adminResult(w, nil, err)
			return
		}
	}

	result, err := api.Config.Public(ctx, "")
	adminResult(w, struct {
		config.PublicConfiguration
		RestartRequired bool `json:"restartRequired"`
	}{result, restart}, err)
}

func (api AdminAPI) restoreTrash(w http.ResponseWriter, r *http.Request, user webauth.Session) {
	body, ok := readObject(w, r)
	if !ok {
		return
	}
	var id string
	if json.Unmarshal(body["id"], &id) != nil {
		writeError(w, http.StatusBadRequest, "Ungültiges Papierkorb-Element")
		return
	}
	share, _, err := trash.DecodeItemID(id)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Ungültiges Papierkorb-Element")
		return
	}

	ctx := r.Context()
	var result trash.RestoreResult
	if share != "Data" {
		result, err = api.Trash.Restore(ctx, id, nil)
	} else {
		err = api.Access.WithMutation(ctx, func(mutation *accesscontrol.Mutation) error {
			var err error
			result, err = api.Trash.Restore(ctx, id, mutation.PrepareDataRestore)
			return err
		})
	}

	switch {
	case errors.Is(err, os.ErrExist):
		writeError(w, http.StatusConflict, "Am Originalpfad existiert bereits eine Datei")
	case errors.Is(err, os.ErrNotExist):
		writeError(w, http.StatusNotFound, "Datei nicht gefunden oder abgelaufen")
	default:
		adminResult(w, result, err)
	}
}
