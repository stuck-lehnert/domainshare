package webapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/stuck-lehnert/domainshare/internal/agenttoken"
	"github.com/stuck-lehnert/domainshare/internal/directory"
	"github.com/stuck-lehnert/domainshare/internal/webauth"
)

const agentAdminPath = "/admin/api/agent-tokens"

type AgentAdmin struct {
	Auth SessionAPI
	API  AgentAPI
}

func (admin AgentAdmin) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	setSecurityHeaders(writer.Header(), false, "no-store")
	path := request.URL.EscapedPath()
	listing := path == agentAdminPath && request.Method == http.MethodGet
	mutation := (path == agentAdminPath || path == agentAdminPath+"/revoke") && request.Method == http.MethodPost
	if !listing && !mutation {
		writeError(writer, http.StatusNotFound, "Nicht gefunden")
		return
	}

	identity, ok := admin.Auth.requireAdmin(writer, request, mutation)
	if !ok {
		return
	}
	store := admin.API.Tokens
	if store == nil {
		admin.unavailable(writer, "store")
		return
	}

	if listing {
		inventory, err := store.Inventory(request.Context())
		if err != nil {
			admin.unavailable(writer, "inventory")
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"tokens": inventory})
		return
	}

	body, ok := readObject(writer, request)
	if !ok {
		return
	}
	if path == agentAdminPath+"/revoke" {
		admin.revoke(writer, request, body, identity)
		return
	}
	admin.issue(writer, request, body, identity)
}

func (admin AgentAdmin) revoke(writer http.ResponseWriter, request *http.Request, body map[string]json.RawMessage, identity webauth.Session) {
	var identifier string
	if json.Unmarshal(body["id"], &identifier) != nil {
		writeError(writer, http.StatusBadRequest, agenttoken.ErrID.Error())
		return
	}
	revoked, err := admin.API.Tokens.Revoke(request.Context(), identifier)
	if errors.Is(err, agenttoken.ErrID) {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	if err != nil {
		admin.unavailable(writer, "revocation")
		return
	}
	if !revoked {
		writeError(writer, http.StatusNotFound, "Token nicht gefunden")
		return
	}
	if admin.API.Logger != nil {
		admin.API.Logger.Info("Agent token revoked", "id", identifier, "adminSID", identity.SID)
	}
	writeJSON(writer, http.StatusOK, map[string]bool{"ok": true})
}

func (admin AgentAdmin) issue(writer http.ResponseWriter, request *http.Request, body map[string]json.RawMessage, identity webauth.Session) {
	var label string
	if json.Unmarshal(body["label"], &label) != nil || strings.TrimSpace(label) == "" || utf8.RuneCountInString(strings.TrimSpace(label)) > 100 {
		writeError(writer, http.StatusBadRequest, "Eine Bezeichnung mit 1 bis 100 Zeichen ist erforderlich")
		return
	}

	days := 30
	if raw, exists := body["expiresInDays"]; exists {
		var requestedDays *int
		if json.Unmarshal(raw, &requestedDays) != nil || (requestedDays != nil && (*requestedDays < 1 || *requestedDays > 365)) {
			writeError(writer, http.StatusBadRequest, "Die Laufzeit muss zwischen 1 und 365 Tagen liegen oder leer bleiben")
			return
		}
		if requestedDays == nil {
			days = agenttoken.NoExpiry
		} else {
			days = *requestedDays
		}
	}

	var usernames []string
	// Only an explicit empty array grants the all-user scope. Missing or null
	// input must not silently broaden a client's intended scope.
	if json.Unmarshal(body["usernames"], &usernames) != nil || usernames == nil || len(usernames) > 10 {
		writeError(writer, http.StatusBadRequest, "usernames muss eine Liste mit höchstens zehn AD-Benutzernamen sein")
		return
	}
	allUsers := len(usernames) == 0
	if !allUsers && admin.API.Accounts == nil {
		admin.unavailable(writer, "directory")
		return
	}

	ctx := request.Context()
	accounts := make(map[string]string)
	for _, username := range usernames {
		sam, err := admin.API.Accounts.AccountLogin(username)
		if err != nil || sam == "" {
			writeError(writer, http.StatusBadRequest, "Ein gültiger Benutzername ist erforderlich")
			return
		}
		sid, err := admin.API.Accounts.ResolveAccount(ctx, sam)
		if errors.Is(err, directory.ErrAccount) {
			writeError(writer, http.StatusBadRequest, "AD-Benutzer nicht verfügbar: "+sam)
			return
		}
		if err != nil || sid == "" {
			admin.unavailable(writer, "account lookup")
			return
		}
		accounts[sid] = sam
	}

	var issued agenttoken.Issued
	var err error
	if allUsers {
		issued, err = admin.API.Tokens.IssueForAllUsers(ctx, label, days, identity.Username)
	} else {
		issued, err = admin.API.Tokens.Issue(ctx, label, accounts, days, identity.Username)
	}
	if err != nil {
		admin.unavailable(writer, "issuance")
		return
	}
	if admin.API.Logger != nil {
		admin.API.Logger.Info("Agent token issued", "id", issued.ID, "adminSID", identity.SID,
			"allUsers", allUsers, "neverExpires", issued.ExpiresAt == nil)
	}
	writeJSON(writer, http.StatusCreated, issued)
}

func (admin AgentAdmin) unavailable(writer http.ResponseWriter, stage string) {
	if admin.API.Logger != nil {
		admin.API.Logger.Warn("Agent token administration unavailable", "stage", stage)
	}
	writeError(writer, http.StatusServiceUnavailable, "Tokenverwaltung nicht verfügbar")
}
