// Package webapi serves the HTTP contracts shared with the browser frontend.
package webapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/stuck-lehnert/domainshare/internal/agenttoken"
	"github.com/stuck-lehnert/domainshare/internal/directory"
	"github.com/stuck-lehnert/domainshare/internal/documents"
)

type AgentDirectory interface {
	AccountLogin(string) (string, error)
	ResolveAccount(context.Context, string) (string, error)
	CurrentIdentity(context.Context, string) (directory.Identity, error)
}

// DocumentRequest is shared with the browser document routes. It receives an
// already authorized identity and a canonical /api/documents path.
type DocumentRequest func(http.ResponseWriter, *http.Request, string, url.Values, directory.Identity)

type AgentAPI struct {
	Tokens   *agenttoken.Store
	Accounts AgentDirectory
	Files    documents.Service
	Indexed  DocumentRequest
	Logger   *slog.Logger
}

const agentPrefix = "/api/agent/v1"

var (
	indexedPath = regexp.MustCompile(`^/documents/[a-f0-9]{32}(?:/(?:download|preview|content))?$`)
	agentBearer = regexp.MustCompile(`(?i)^Bearer ([^\s]+)$`)
)

func (api AgentAPI) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	setSecurityHeaders(writer.Header(), false, "no-store")
	operation, ok := strings.CutPrefix(request.URL.EscapedPath(), agentPrefix)
	indexed := indexedPath.MatchString(operation)
	if !ok || (!indexed && operation != "/search" && operation != "/list" && operation != "/file") {
		writeError(writer, http.StatusNotFound, "Agenten-Endpunkt nicht gefunden")
		return
	}
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		writeError(writer, http.StatusMethodNotAllowed, "Agenten-Endpunkt ist nur lesbar")
		return
	}
	if request.TLS == nil {
		writeError(writer, http.StatusForbidden, "HTTPS ist für den Agenten-Endpunkt erforderlich")
		return
	}

	headers := request.Header.Values("Authorization")
	if len(headers) != 1 || len(headers[0]) > 256 || api.Tokens == nil {
		writeError(writer, http.StatusUnauthorized, "Agenten-Token erforderlich")
		return
	}
	match := agentBearer.FindStringSubmatch(headers[0])
	if match == nil {
		writeError(writer, http.StatusUnauthorized, "Agenten-Token erforderlich")
		return
	}

	ctx := request.Context()
	token, err := api.Tokens.Authenticate(ctx, match[1])
	if errors.Is(err, agenttoken.ErrInvalid) {
		writeError(writer, http.StatusUnauthorized, "Agenten-Token ungültig oder abgelaufen")
		return
	}
	if err != nil || api.Accounts == nil {
		api.unavailable(writer, "token lookup")
		return
	}

	params, err := agentParams(request.URL.RawQuery)
	if err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	sam, err := api.Accounts.AccountLogin(params.Get("username"))
	if err != nil || sam == "" {
		writeError(writer, http.StatusBadRequest, "Ein gültiger Benutzername ist erforderlich")
		return
	}

	sid, err := api.Accounts.ResolveAccount(ctx, sam)
	if err != nil && !errors.Is(err, directory.ErrAccount) {
		api.unavailable(writer, "directory lookup")
		return
	}
	const denied = "Benutzer ist für diesen Token nicht freigegeben"
	_, scoped := token.Accounts[sid]
	if err != nil || sid == "" || (!token.AllUsers && !scoped) {
		writeError(writer, http.StatusForbidden, denied)
		return
	}
	identity, err := api.Accounts.CurrentIdentity(ctx, sid)
	if err != nil || identity.SID != sid || identity.Username == "" ||
		(identity.Role != "user" && !identity.Admin()) || directory.IsExcludedUser(identity.Username) {
		writeError(writer, http.StatusForbidden, denied)
		return
	}
	if api.Logger != nil {
		api.Logger.Info("Agent token used", "id", token.ID, "sid", sid, "operation", operation)
	}

	if operation == "/search" || indexed {
		if api.Indexed == nil {
			api.unavailable(writer, "catalog unavailable")
			return
		}
		path := "/api" + operation
		if operation == "/search" {
			path = "/api/documents"
		}
		api.Indexed(writer, request, path, params, identity)
		return
	}
	api.browse(writer, request, operation, params, identity)
}

func agentParams(query string) (url.Values, error) {
	if len(query) > 64*1024 || strings.Count(query, "&") >= 24 {
		return nil, errors.New("Zu viele oder zu lange Anfrageparameter")
	}
	// The Python parser treats semicolons as data, not field separators.
	params, err := url.ParseQuery(strings.ReplaceAll(query, ";", "%3B"))
	if err != nil {
		return nil, errors.New("Ungültige Anfrageparameter")
	}
	for name, values := range params {
		if len(values) != 1 {
			return nil, errors.New("Anfrageparameter dürfen nur einmal vorkommen")
		}
		if !utf8.ValidString(name) || !utf8.ValidString(values[0]) {
			return nil, errors.New("Ungültige Anfrageparameter")
		}
	}
	return params, nil
}

func (api AgentAPI) browse(writer http.ResponseWriter, request *http.Request, operation string, params url.Values, identity directory.Identity) {
	source, relative := params.Get("source"), params.Get("path")
	if utf8.RuneCountInString(source) > 300 || utf8.RuneCountInString(relative) > 4096 {
		writeError(writer, http.StatusBadRequest, "Dateipfad oder Ordnerkennung zu lang")
		return
	}
	if api.Files.Policy == nil || api.Files.Catalog == nil {
		api.unavailable(writer, "file policy unavailable")
		return
	}

	ctx := request.Context()
	if operation == "/file" {
		if source == "" || relative == "" {
			writeError(writer, http.StatusBadRequest, "source und path sind für Dateiabrufe erforderlich")
			return
		}
		file, err := api.Files.DownloadPath(ctx, identity, source, relative)
		if err != nil {
			api.browseError(writer, err)
			return
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			api.browseError(writer, err)
			return
		}
		writeFile(writer, request, file, info.Size(), "application/octet-stream", file.Name(), "attachment", true)
		return
	}

	if source != "" {
		after := params.Get("after")
		limit := 100
		var err error
		if params.Has("limit") {
			limit, err = strconv.Atoi(strings.TrimSpace(params.Get("limit")))
		}
		if err != nil || limit < 1 || limit > 200 || utf8.RuneCountInString(after) > 255 {
			writeError(writer, http.StatusBadRequest, "Ungültiger Seitenzeiger oder Seitenumfang")
			return
		}
		page, err := api.Files.BrowseDirectory(ctx, identity, source, relative, after, limit)
		if err != nil {
			api.browseError(writer, err)
			return
		}
		writeJSON(writer, http.StatusOK, page)
		return
	}

	if relative != "" || params.Has("after") {
		writeError(writer, http.StatusBadRequest, "source ist für Ordnerpfade erforderlich")
		return
	}
	sources, err := api.Files.BrowseSources(ctx, identity)
	if err != nil {
		api.browseError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"sources": sources})
}

func (api AgentAPI) browseError(writer http.ResponseWriter, err error) {
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
		writeError(writer, http.StatusNotFound, "Datei oder Ordner nicht verfügbar")
		return
	}
	api.unavailable(writer, "filesystem lookup")
}

func (api AgentAPI) unavailable(writer http.ResponseWriter, stage string) {
	if api.Logger != nil {
		// Never log Authorization headers or the query string.
		api.Logger.Warn("Agent API unavailable", "stage", stage)
	}
	writeError(writer, http.StatusServiceUnavailable, "Agenten-API nicht verfügbar")
}
