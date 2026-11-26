package webapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/stuck-lehnert/domainshare/internal/accesscontrol"
	"github.com/stuck-lehnert/domainshare/internal/audit"
	"github.com/stuck-lehnert/domainshare/internal/config"
	"github.com/stuck-lehnert/domainshare/internal/documents"
	"github.com/stuck-lehnert/domainshare/internal/trash"
	"github.com/stuck-lehnert/domainshare/internal/webauth"
)

type AdminAPI struct {
	Auth      SessionAPI
	Config    *config.Store
	Directory BootstrapDirectory
	Users     func(context.Context, bool) (map[string]accesscontrol.Principal, map[string]accesscontrol.Principal, error)
	Access    *accesscontrol.Service
	Documents *sql.DB
	Audit     *audit.Store
	Trash     *trash.Service
	Usage     UsageScanner
	Action    func(context.Context, string) error
}

func (api AdminAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w.Header(), false, "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		writeError(w, http.StatusMethodNotAllowed, "Methode nicht erlaubt")
		return
	}
	user, ok := api.Auth.requireAdmin(w, r, r.Method == http.MethodPost)
	if !ok {
		return
	}
	path := strings.TrimPrefix(r.URL.EscapedPath(), "/admin/api/")
	params, err := url.ParseQuery(strings.ReplaceAll(r.URL.RawQuery, ";", "%3B"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "Ungültige Anfrageparameter")
		return
	}
	if r.Method == http.MethodGet {
		api.get(w, r, path, params)
		return
	}
	api.post(w, r, path, user)
}

func adminResult(w http.ResponseWriter, payload any, err error) {
	if err == nil {
		writeJSON(w, http.StatusOK, payload)
		return
	}
	var conflict accesscontrol.Conflict
	var invalid accesscontrol.Invalid
	switch {
	case errors.As(err, &conflict):
		writeError(w, http.StatusConflict, conflict.Error())
	case errors.As(err, &invalid):
		writeError(w, http.StatusBadRequest, invalid.Error())
	case errors.Is(err, config.ErrConflict):
		writeError(w, http.StatusConflict, "Einstellungen wurden inzwischen geändert")
	default:
		writeError(w, http.StatusBadRequest, "Anfrage konnte nicht verarbeitet werden")
	}
}

func (api AdminAPI) get(w http.ResponseWriter, r *http.Request, path string, params url.Values) {
	ctx := r.Context()
	switch path {
	case "settings":
		result, err := api.Config.Public(ctx, params.Get("section"))
		adminResult(w, result, err)
	case "settings/groups":
		groups, err := api.Directory.ListGroups(ctx)
		adminResult(w, map[string]any{"groups": groups}, err)
	case "access":
		users, _, err := api.Users(ctx, false)
		if err != nil {
			adminResult(w, nil, err)
			return
		}
		result, err := api.Access.Snapshot(ctx, users)
		adminResult(w, result, err)
	case "documents/status":
		result, err := documents.WorkerSnapshot(ctx, api.Documents)
		adminResult(w, result, err)
	case "activity", "fslogix-activity":
		api.activity(w, r, path, params)
	case "overview", "groups", "storage", "backup", "reconciliation", "system", "report":
		api.status(w, r, path, params)
	case "trash":
		limit := trash.DefaultLimit
		if params.Has("limit") {
			var err error
			limit, err = strconv.Atoi(params.Get("limit"))
			if err != nil {
				writeError(w, http.StatusBadRequest, "Ungültige Trefferzahl")
				return
			}
		}
		result, err := api.Trash.List(ctx, trash.ListOptions{Share: params.Get("share"), Path: params.Get("path"), Limit: limit})
		adminResult(w, result, err)
	case "trash/download":
		file, item, err := api.Trash.OpenDownload(ctx, params.Get("id"))
		if err != nil {
			writeError(w, http.StatusNotFound, "Papierkorb-Element nicht verfügbar")
			return
		}
		defer file.Close()
		writeFile(w, r, file, item.Size, "application/octet-stream", item.Name, "attachment", false)
	default:
		writeError(w, http.StatusNotFound, "Nicht gefunden")
	}
}

func (api AdminAPI) activity(w http.ResponseWriter, r *http.Request, path string, params url.Values) {
	ctx := r.Context()
	today := time.Now().UTC().Truncate(24 * time.Hour)
	start, end := today.AddDate(0, 0, -1), today
	for key, target := range map[string]*time.Time{"from": &start, "to": &end} {
		if params.Has(key) {
			parsed, err := time.Parse(time.DateOnly, params.Get(key))
			if err != nil {
				writeError(w, http.StatusBadRequest, "Datumsangaben müssen YYYY-MM-DD verwenden")
				return
			}
			*target = parsed
		}
	}
	snapshot, err := api.Config.Snapshot(ctx)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Konfiguration ist nicht verfügbar")
		return
	}
	days := snapshot.Values.Int("AUDIT_QUERY_MAX_DAYS")
	if days < 1 || days > 366 {
		days = 31
	}
	if end.Before(start) || !end.Before(start.AddDate(0, 0, days)) {
		writeError(w, http.StatusBadRequest, "Der Datumsbereich darf höchstens "+strconv.Itoa(days)+" Tage umfassen")
		return
	}
	stream := "main"
	if path == "fslogix-activity" {
		stream = "fslogix"
	}
	result, err := api.Audit.QueryActivity(ctx, start, end, params, stream)
	adminResult(w, result, err)
}

func (api AdminAPI) post(w http.ResponseWriter, r *http.Request, path string, user webauth.Session) {
	ctx := r.Context()
	switch path {
	case "settings", "settings/backup-key/generate", "settings/backup-key/activate":
		api.settingsWrite(w, r, path, user)
	case "documents/control":
		body, ok := readObject(w, r)
		if !ok {
			return
		}
		var action string
		if json.Unmarshal(body["action"], &action) != nil {
			writeError(w, http.StatusBadRequest, "Ungültige Aktion")
			return
		}
		result, err := documents.ControlWorker(ctx, api.Documents, action, user.Username)
		adminResult(w, result, err)
	case "access":
		body, ok := readValues(w, r, 256*1024)
		if !ok {
			return
		}
		users, _, err := api.Users(ctx, false)
		if err != nil {
			adminResult(w, nil, err)
			return
		}
		result, err := api.Access.ApplyChange(ctx, body, user.Username, users)
		adminResult(w, result, err)
	case "trash/restore":
		api.restoreTrash(w, r, user)
	case "actions/backup", "actions/reconciliation":
		api.startAction(w, r, strings.TrimPrefix(path, "actions/"), user)
	default:
		writeError(w, http.StatusNotFound, "Nicht gefunden")
	}
}
