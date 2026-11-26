package webauth

import (
	"crypto/hmac"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/text/cases"
)

var ErrOrigin = errors.New("Nicht vertrauenswürdiger Origin")

type origin struct {
	host string
	port int
}

func parseOrigin(value string) (origin, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil ||
		parsed.Path != "" || strings.ContainsAny(value, "?#") || strings.HasSuffix(parsed.Host, ":") ||
		strings.IndexFunc(value, unicode.IsSpace) >= 0 {
		return origin{}, ErrOrigin
	}
	port := 443
	if text := parsed.Port(); text != "" {
		port, err = strconv.Atoi(text)
		if err != nil || port < 1 || port > 65535 {
			return origin{}, ErrOrigin
		}
	}
	return origin{host: cases.Fold().String(parsed.Hostname()), port: port}, nil
}

type Origins struct{ allowed map[origin]struct{} }

func NewOrigins(values string) (Origins, error) {
	allowed := make(map[origin]struct{})
	for _, value := range strings.Split(values, ",") {
		parsed, err := parseOrigin(strings.TrimSpace(value))
		if err != nil {
			return Origins{}, err
		}
		allowed[parsed] = struct{}{}
	}
	return Origins{allowed: allowed}, nil
}

// Allows checks configured origins, never the request's Host or proxy headers.
// Requests without Origin are handled separately by the CSRF check.
func (origins Origins) Allows(request *http.Request) bool {
	for _, site := range request.Header.Values("Sec-Fetch-Site") {
		if site == "cross-site" || site == "same-site" {
			return false
		}
	}
	values := request.Header.Values("Origin")
	if len(values) == 0 {
		return true
	}
	if len(values) != 1 {
		return false
	}
	parsed, err := parseOrigin(values[0])
	_, ok := origins.allowed[parsed]
	return err == nil && ok
}

func bearer(request *http.Request) (string, bool) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}
	raw, ok := strings.CutPrefix(values[0], "Bearer ")
	return strings.TrimSpace(raw), ok
}

func RequestToken(request *http.Request) string {
	if raw, ok := bearer(request); ok {
		return raw
	}
	if len(request.Header.Values("Authorization")) > 1 {
		return ""
	}
	cookie, err := request.Cookie(CookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func (manager *Manager) CheckCSRF(origins Origins, request *http.Request, session Session) bool {
	if !origins.Allows(request) {
		return false
	}
	if len(request.Header.Values("Origin")) == 0 {
		raw, ok := bearer(request)
		if !ok || raw == "" {
			return false
		}
	}
	values := request.Header.Values("X-CSRF-Token")
	return len(values) == 1 && session.ID != "" && hmac.Equal([]byte(values[0]), []byte(manager.CSRF(session)))
}
