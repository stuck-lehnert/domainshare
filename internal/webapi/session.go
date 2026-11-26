package webapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/stuck-lehnert/domainshare/internal/directory"
	"github.com/stuck-lehnert/domainshare/internal/webauth"
	"golang.org/x/text/cases"
)

type SessionAPI struct {
	Sessions *webauth.Manager
	Origins  webauth.Origins
	Limiter  *LoginLimiter
	Login    func(context.Context, string, string) (directory.Identity, error)
	Remember func(context.Context, directory.Identity) error
}

func (api SessionAPI) requireSession(writer http.ResponseWriter, request *http.Request, refresh bool) (webauth.Session, bool) {
	if api.Sessions == nil || request.TLS == nil {
		writeError(writer, http.StatusServiceUnavailable, "Anmeldung nicht verfügbar")
		return webauth.Session{}, false
	}
	session, err := api.Sessions.Verify(request.Context(), webauth.RequestToken(request), refresh)
	if err == nil {
		return session, true
	}
	if errors.Is(err, webauth.ErrSession) {
		writeError(writer, http.StatusUnauthorized, "Anmeldung erforderlich")
	} else {
		writeError(writer, http.StatusServiceUnavailable, "Anmeldung nicht verfügbar")
	}
	return webauth.Session{}, false
}

func (api SessionAPI) requireAdmin(writer http.ResponseWriter, request *http.Request, mutation bool) (webauth.Session, bool) {
	if mutation && !api.allowJSONWrite(writer, request) {
		return webauth.Session{}, false
	}
	session, ok := api.requireSession(writer, request, true)
	if !ok {
		return webauth.Session{}, false
	}
	if mutation && !api.requireCSRF(writer, request, session) {
		return webauth.Session{}, false
	}
	if !session.Admin() {
		writeError(writer, http.StatusForbidden, "Domänenadministrator erforderlich")
		return webauth.Session{}, false
	}
	return session, true
}

func (api SessionAPI) requireCSRF(writer http.ResponseWriter, request *http.Request, session webauth.Session) bool {
	if api.Sessions.CheckCSRF(api.Origins, request, session) {
		return true
	}
	writeError(writer, http.StatusForbidden, "Ungültiger CSRF-Schutz")
	return false
}

func (api SessionAPI) allowJSONWrite(writer http.ResponseWriter, request *http.Request) bool {
	media, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || len(request.Header.Values("Content-Type")) != 1 {
		writeError(writer, http.StatusUnsupportedMediaType, "application/json erforderlich")
		return false
	}
	if request.TLS == nil || !api.Origins.Allows(request) {
		writeError(writer, http.StatusForbidden, "Nicht vertrauenswürdiger Origin")
		return false
	}
	return true
}

func readObject(writer http.ResponseWriter, request *http.Request) (map[string]json.RawMessage, bool) {
	return readBoundedObject(writer, request, 16*1024)
}

func readBoundedObject(writer http.ResponseWriter, request *http.Request, limit int64) (map[string]json.RawMessage, bool) {
	reader := http.MaxBytesReader(writer, request.Body, limit)
	defer reader.Close()
	decoder := json.NewDecoder(reader)
	var body map[string]json.RawMessage
	if err := decoder.Decode(&body); err != nil || body == nil || decoder.Decode(new(any)) != io.EOF {
		writeError(writer, http.StatusBadRequest, "Ein gültiges JSON-Objekt ist erforderlich")
		return nil, false
	}
	return body, true
}

func (api SessionAPI) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	setSecurityHeaders(writer.Header(), false, "no-store")
	path := request.URL.EscapedPath()
	switch {
	case request.Method == http.MethodPost && path == "/api/login":
		api.login(writer, request)
	case request.Method == http.MethodPost && path == "/api/logout":
		api.logout(writer, request)
	case request.Method == http.MethodGet && path == "/api/session":
		if session, ok := api.requireSession(writer, request, true); ok {
			writeJSON(writer, http.StatusOK, api.sessionPayload(session))
		}
	case request.Method == http.MethodGet && path == "/admin/api/session":
		if session, ok := api.requireAdmin(writer, request, false); ok {
			writeJSON(writer, http.StatusOK, map[string]any{"user": session.Username, "expiresAt": session.ExpiresAt})
		}
	default:
		writeError(writer, http.StatusNotFound, "Nicht gefunden")
	}
}

func (api SessionAPI) sessionPayload(session webauth.Session) map[string]any {
	return map[string]any{"user": session.Username, "sid": session.SID, "role": session.Role,
		"expiresAt": session.ExpiresAt, "csrfToken": api.Sessions.CSRF(session)}
}

func (api SessionAPI) login(writer http.ResponseWriter, request *http.Request) {
	if !api.allowJSONWrite(writer, request) {
		return
	}
	if headers := request.Header.Values("X-CSRF-Token"); len(headers) != 1 || headers[0] != "login" {
		writeError(writer, http.StatusForbidden, "Ungültiger CSRF-Schutz")
		return
	}
	if api.Sessions == nil || api.Login == nil || api.Remember == nil || api.Limiter == nil {
		writeError(writer, http.StatusServiceUnavailable, "Anmeldung nicht verfügbar")
		return
	}
	body, ok := readObject(writer, request)
	if !ok {
		return
	}
	var username, password string
	if json.Unmarshal(body["username"], &username) != nil || json.Unmarshal(body["password"], &password) != nil {
		writeError(writer, http.StatusBadRequest, "Benutzername und Passwort sind erforderlich")
		return
	}
	remote, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		remote = request.RemoteAddr
	}
	if !api.Limiter.Reserve(remote, username) {
		writeError(writer, http.StatusTooManyRequests, "Zu viele Anmeldeversuche; bitte später erneut versuchen")
		return
	}
	ctx := request.Context()
	identity, err := api.Login(ctx, username, password)
	if err != nil {
		timer := time.NewTimer(400 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			writeError(writer, http.StatusUnauthorized, "Ungültige Zugangsdaten")
			return
		}
	}
	if err := api.Remember(ctx, identity); err != nil {
		writeError(writer, http.StatusServiceUnavailable, "Anmeldung nicht verfügbar")
		return
	}
	token, session, err := api.Sessions.Issue(ctx, identity)
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "Anmeldung nicht verfügbar")
		return
	}
	http.SetCookie(writer, sessionCookie(token, int(max(1, session.ExpiresAt-time.Now().Unix()))))
	payload := api.sessionPayload(session)
	payload["token"], payload["tokenType"] = token, "Bearer"
	writeJSON(writer, http.StatusOK, payload)
}

func (api SessionAPI) logout(writer http.ResponseWriter, request *http.Request) {
	if !api.allowJSONWrite(writer, request) {
		return
	}
	// Logout must still work when the directory is unavailable.
	session, ok := api.requireSession(writer, request, false)
	if !ok || !api.requireCSRF(writer, request, session) {
		return
	}
	if err := api.Sessions.Revoke(request.Context(), session); err != nil {
		writeError(writer, http.StatusServiceUnavailable, "Sitzung konnte nicht beendet werden")
		return
	}
	http.SetCookie(writer, sessionCookie("", -1))
	writeJSON(writer, http.StatusOK, map[string]bool{"ok": true})
}

func sessionCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{Name: webauth.CookieName, Value: value, MaxAge: maxAge, Path: "/", HttpOnly: true,
		Secure: true, SameSite: http.SameSiteStrictMode}
}

// LoginLimiter applies a sliding window by remote IP and account, regardless
// of whether the caller supplies a bare username, DOMAIN\user or UPN.
type LoginLimiter struct {
	mu           sync.Mutex
	ipLimit      int
	accountLimit int
	attempts     map[string][]time.Time
	now          func() time.Time
}

func NewLoginLimiter(ipLimit, accountLimit int) *LoginLimiter {
	return &LoginLimiter{ipLimit: max(3, min(100, ipLimit)), accountLimit: max(3, min(100, accountLimit)),
		attempts: make(map[string][]time.Time), now: time.Now}
}

func (limiter *LoginLimiter) Reserve(ip, username string) bool {
	name := strings.TrimSpace(username)
	name = name[strings.LastIndexByte(name, '\\')+1:]
	name, _, _ = strings.Cut(name, "@")
	runes := []rune(cases.Fold().String(name))
	name = string(runes[:min(len(runes), 256)])
	ipKey, accountKey := "ip:"+ip, "account:"+name

	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	now := limiter.now()
	cutoff := now.Add(-5 * time.Minute)
	for key, attempts := range limiter.attempts {
		first := 0
		for first < len(attempts) && !attempts[first].After(cutoff) {
			first++
		}
		if first == len(attempts) {
			delete(limiter.attempts, key)
		} else {
			limiter.attempts[key] = attempts[first:]
		}
	}
	// Bound memory even when numerous distinct usernames/IPs arrive together.
	if len(limiter.attempts) >= 8192 || len(limiter.attempts[ipKey]) >= limiter.ipLimit ||
		len(limiter.attempts[accountKey]) >= limiter.accountLimit {
		return false
	}
	limiter.attempts[ipKey] = append(limiter.attempts[ipKey], now)
	limiter.attempts[accountKey] = append(limiter.attempts[accountKey], now)
	return true
}
