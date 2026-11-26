package webapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"

	"github.com/stuck-lehnert/domainshare/internal/config"
	"github.com/stuck-lehnert/domainshare/internal/directory"
	"github.com/stuck-lehnert/domainshare/internal/tlssetup"
	"github.com/stuck-lehnert/domainshare/internal/webauth"
)

type BootstrapDirectory interface {
	ListGroups(context.Context) ([]directory.Group, error)
	Authenticate(context.Context, string, string) (directory.Identity, error)
	CurrentIdentityWithAdminSID(context.Context, string, string) (directory.Identity, error)
}

type BootstrapAPI struct {
	Store     *config.Store
	RunRoot   string
	Origins   func(config.Snapshot) webauth.Origins
	Directory func(config.Snapshot) BootstrapDirectory
}

func (api BootstrapAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w.Header(), false, "no-store")
	if r.TLS == nil || api.Store == nil {
		writeError(w, http.StatusNotFound, "Nicht gefunden")
		return
	}

	snapshot, err := api.Store.Snapshot(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Konfiguration ist nicht verfügbar")
		return
	}
	path := r.URL.EscapedPath()
	configured := snapshot.Phase == "configured"
	if r.Method == http.MethodGet && path == "/api/bootstrap/status" {
		writeJSON(w, http.StatusOK, map[string]any{"phase": snapshot.Phase, "configured": configured})
		return
	}

	code := r.Header.Values("X-Setup-Token")
	valid := false
	if !configured && len(code) == 1 {
		valid, err = api.Store.MatchesSetupCode(code[0], false)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "Einrichtung ist nicht verfügbar")
			return
		}
	}
	if !valid {
		writeError(w, http.StatusForbidden, "Ungültiger Einrichtungscode oder Einrichtung abgeschlossen")
		return
	}

	if r.Method == http.MethodPost {
		if api.Origins == nil {
			writeError(w, http.StatusServiceUnavailable, "Einrichtung ist nicht verfügbar")
			return
		}
		if !(SessionAPI{Origins: api.Origins(snapshot)}).allowJSONWrite(w, r) {
			return
		}
	}

	switch {
	case r.Method == http.MethodGet && path == "/api/bootstrap/settings":
		api.settings(w, snapshot)
	case r.Method == http.MethodGet && path == "/api/bootstrap/groups":
		_, groups, ok := api.groups(w, r, snapshot)
		if ok {
			writeJSON(w, http.StatusOK, map[string]any{"groups": groups})
		}
	case r.Method == http.MethodPost && (path == "/api/bootstrap/domain" || path == "/api/bootstrap/finish"):
		api.submit(w, r, snapshot, path == "/api/bootstrap/finish")
	case r.Method == http.MethodPost && path == "/api/bootstrap/import":
		api.importLegacy(w, r)
	default:
		writeError(w, http.StatusNotFound, "Nicht gefunden")
	}
}

func (api BootstrapAPI) settings(w http.ResponseWriter, snapshot config.Snapshot) {
	public, err := snapshot.Public("")
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Konfiguration ist nicht verfügbar")
		return
	}

	status := tlssetup.Status{State: "waiting"}
	if file, err := os.Open(filepath.Join(api.Store.Root(), "services-status.json")); err == nil {
		defer file.Close()
		var current tlssetup.Status
		if json.NewDecoder(io.LimitReader(file, 16*1024)).Decode(&current) == nil && current.State != "" {
			status = current
		}
	}
	writeJSON(w, http.StatusOK, struct {
		config.PublicConfiguration
		Services tlssetup.Status `json:"services"`
	}{public, status})
}

func (api BootstrapAPI) groups(w http.ResponseWriter, r *http.Request, snapshot config.Snapshot) (BootstrapDirectory, []directory.Group, bool) {
	ready, err := os.Stat(filepath.Join(api.RunRoot, "domainshare-domain-ready"))
	if snapshot.Phase != "groups" || err != nil || !ready.Mode().IsRegular() || api.Directory == nil {
		writeError(w, http.StatusBadRequest, "Domänenbeitritt ist noch nicht abgeschlossen")
		return nil, nil, false
	}

	client := api.Directory(snapshot)
	if client == nil {
		writeError(w, http.StatusServiceUnavailable, "Gruppen sind nicht verfügbar")
		return nil, nil, false
	}
	groups, err := client.ListGroups(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Gruppen sind nicht verfügbar")
		return nil, nil, false
	}
	if groups == nil {
		groups = []directory.Group{}
	}
	return client, groups, true
}

func (api BootstrapAPI) submit(w http.ResponseWriter, r *http.Request, snapshot config.Snapshot, finish bool) {
	body, ok := readBoundedObject(w, r, 256*1024)
	if !ok {
		return
	}

	var revision *int64
	if json.Unmarshal(body["revision"], &revision) != nil || revision == nil || *revision != snapshot.Revision {
		writeError(w, http.StatusConflict, "Einstellungen wurden inzwischen geändert")
		return
	}
	var changes config.Values
	values := json.NewDecoder(bytes.NewReader(body["values"]))
	values.UseNumber()
	if values.Decode(&changes) != nil || changes == nil {
		writeError(w, http.StatusBadRequest, "Einstellungen müssen als Objekt angegeben werden")
		return
	}

	if finish {
		api.finish(w, r, snapshot, changes, body)
		return
	}
	if err := api.Store.SubmitDomain(r.Context(), changes, *revision); err != nil {
		setupWriteError(w, err, "Domänen- und HTTPS-Einstellungen prüfen")
		return
	}
	public, err := api.Store.Public(r.Context(), "")
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Konfiguration ist nicht verfügbar")
		return
	}
	writeJSON(w, http.StatusAccepted, public)
}

func (api BootstrapAPI) finish(w http.ResponseWriter, r *http.Request, snapshot config.Snapshot, changes config.Values, body map[string]json.RawMessage) {
	groupFields := []string{"DOMAIN_USERS_SID", "DOMAIN_ADMINS_SID", "FSLOGIX_GROUP_SID"}
	if len(changes) != len(groupFields) {
		writeError(w, http.StatusBadRequest, "Benutzer-, Administratoren- und FSLogix-Gruppe auswählen")
		return
	}

	client, groups, ok := api.groups(w, r, snapshot)
	if !ok {
		return
	}
	for _, field := range groupFields {
		sid := changes.String(field)
		if !directory.DomainSID(sid) || !slices.ContainsFunc(groups, func(group directory.Group) bool { return group.SID == sid }) {
			writeError(w, http.StatusBadRequest, "Ausgewählte Gruppe ist nicht im aktuellen AD vorhanden")
			return
		}
	}

	username, password := snapshot.Values.String("JOIN_USER"), snapshot.Values.String("JOIN_PASSWORD")
	for key, target := range map[string]*string{"username": &username, "password": &password} {
		if raw, exists := body[key]; exists {
			var text *string
			if json.Unmarshal(raw, &text) != nil || text == nil {
				writeError(w, http.StatusBadRequest, "Benutzername und Passwort sind erforderlich")
				return
			}
			*target = *text
		}
	}

	ctx := r.Context()
	identity, err := client.Authenticate(ctx, username, password)
	if err == nil {
		identity, err = client.CurrentIdentityWithAdminSID(ctx, identity.SID, changes.String("DOMAIN_ADMINS_SID"))
	}
	if err != nil || identity.Role != "domain-admin" {
		writeError(w, http.StatusBadRequest, "Das Einrichtungskonto muss zur ausgewählten Administratorengruppe gehören")
		return
	}
	if err := api.Store.CompleteSetup(ctx, changes, snapshot.Revision); err != nil {
		setupWriteError(w, err, "Einrichtung konnte nicht abgeschlossen werden")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"configured": true, "hostname": snapshot.Values.String("WEB_HOSTNAME")})
}

func (api BootstrapAPI) importLegacy(w http.ResponseWriter, r *http.Request) {
	body, ok := readBoundedObject(w, r, 256*1024)
	if !ok {
		return
	}
	var text string
	if json.Unmarshal(body["text"], &text) != nil || text == "" {
		writeError(w, http.StatusBadRequest, "Frühere Konfiguration ist unvollständig")
		return
	}
	imported, err := api.Store.ImportSetup(r.Context(), text)
	if err != nil || !imported {
		setupWriteError(w, err, "Frühere Konfiguration ungültig oder enthält serverlokale Einstellungen (siehe import-legacy)")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"configured": true})
}

func setupWriteError(w http.ResponseWriter, err error, message string) {
	if errors.Is(err, config.ErrConflict) {
		writeError(w, http.StatusConflict, "Einstellungen wurden inzwischen geändert")
		return
	}
	writeError(w, http.StatusBadRequest, message)
}
