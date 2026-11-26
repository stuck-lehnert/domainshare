package webapi

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/stuck-lehnert/domainshare/internal/directory"
	"github.com/stuck-lehnert/domainshare/internal/documents"
)

type DocumentAPI struct {
	Sessions  SessionAPI
	Files     documents.Service
	StateRoot string
}

func (api DocumentAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w.Header(), false, "no-store")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, "Nur lesender Zugriff möglich")
		return
	}
	session, ok := api.Sessions.requireSession(w, r, true)
	if !ok {
		return
	}
	params, err := url.ParseQuery(strings.ReplaceAll(r.URL.RawQuery, ";", "%3B"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "Ungültige Anfrageparameter")
		return
	}
	identity := directory.Identity{SID: session.SID, Username: session.Username, UID: session.UID, Role: session.Role}
	api.ServeIdentity(w, r, r.URL.EscapedPath(), params, identity)
}

// ServeIdentity is shared by browser and agent requests, after their respective
// authentication and authorization checks.
func (api DocumentAPI) ServeIdentity(w http.ResponseWriter, r *http.Request, path string, params url.Values, identity directory.Identity) {
	if api.Files.Catalog == nil || api.Files.Policy == nil {
		writeError(w, http.StatusServiceUnavailable, "Dokumentindex nicht verfügbar")
		return
	}
	ctx := r.Context()
	if path == "/api/documents" {
		result, err := api.Files.Search(ctx, identity, params)
		if err != nil {
			documentError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
		return
	}
	operation, ok := strings.CutPrefix(path, "/api")
	if !ok || !indexedPath.MatchString(operation) {
		documentError(w, os.ErrNotExist)
		return
	}
	id, kind, _ := strings.Cut(strings.TrimPrefix(operation, "/documents/"), "/")
	switch kind {
	case "":
		result, err := api.Files.Detail(ctx, identity, id)
		if err != nil {
			documentError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	case "preview":
		file, err := api.Files.Preview(ctx, identity, id, api.StateRoot)
		if err != nil {
			documentError(w, err)
			return
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			documentError(w, err)
			return
		}
		writeFile(w, r, file, info.Size(), "image/jpeg", "", "", false)
	case "download", "content":
		file, document, err := api.Files.Download(ctx, identity, id)
		if err != nil {
			documentError(w, err)
			return
		}
		defer file.Close()
		if kind == "download" {
			writeFile(w, r, file, document.Size, "application/octet-stream", document.Name, "attachment", false)
			return
		}
		if document.Extension != ".pdf" {
			documentError(w, os.ErrNotExist)
			return
		}
		writeFile(w, r, file, document.Size, "application/pdf", document.Name, "inline", true)
	}
}

func documentError(w http.ResponseWriter, err error) {
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "Datei nicht verfügbar")
		return
	}
	writeError(w, http.StatusBadRequest, "Dateien konnten nicht geladen werden")
}
