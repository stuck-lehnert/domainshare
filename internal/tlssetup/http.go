package tlssetup

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/stuck-lehnert/domainshare/internal/config"
	"github.com/stuck-lehnert/domainshare/internal/securefile"
)

const (
	challengePrefix = "/.well-known/acme-challenge/"
	maxChallenge    = 16 * 1024
	maxConfig       = 128 * 1024
	setupOnly       = "Über HTTP ist ausschließlich die HTTPS-Einrichtung verfügbar"
)

var challengeToken = regexp.MustCompile(`^[A-Za-z0-9_-]{1,512}$`)

type setup struct {
	store    *config.Store
	assets   fs.FS
	client   *http.Client
	capacity chan struct{}
	mu       sync.Mutex
}

// HTTPHandler serves only HTTPS setup and forwards challenges to the local ACME responder.
func HTTPHandler(store *config.Store, assets fs.FS) http.Handler {
	return &setup{
		store: store, assets: assets, capacity: make(chan struct{}, 32),
		client: &http.Client{
			Transport: &http.Transport{DisableKeepAlives: true},
			Timeout:   5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (server *setup) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")

	select {
	case server.capacity <- struct{}{}:
		defer func() { <-server.capacity }()
	default:
		replyError(w, http.StatusServiceUnavailable, "HTTPS-Einrichtung ist ausgelastet")
		return
	}

	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, challengePrefix) {
		server.challenge(w, r)
		return
	}

	snapshot, err := server.store.Snapshot(r.Context())
	if err != nil {
		replyError(w, http.StatusServiceUnavailable, "Konfiguration ist nicht verfügbar")
		return
	}

	switch r.Method {
	case http.MethodGet:
		server.get(w, r, snapshot)
	case http.MethodPost:
		server.configure(w, r, snapshot)
	default:
		replyError(w, http.StatusMethodNotAllowed, setupOnly)
	}
}

func (server *setup) get(w http.ResponseWriter, r *http.Request, snapshot config.Snapshot) {
	host := snapshot.Values.String("WEB_HOSTNAME")
	authority := host
	port := snapshot.Values.String("WEB_HTTPS_PORT")
	if port != "" && port != "443" {
		authority = net.JoinHostPort(host, port)
	}
	location := (&url.URL{Scheme: "https", Host: authority, Path: "/"}).String()
	configured := snapshot.Phase == "configured"

	if r.URL.Path == "/api/https/status" {
		status := ReadStatus(server.store.Root())
		replyJSON(w, http.StatusOK, map[string]any{
			"state": status.State, "message": status.Message, "hostname": host,
			"httpsUrl": location, "configured": configured,
		})
		return
	}
	if configured {
		w.Header().Set("Location", location)
		w.WriteHeader(http.StatusPermanentRedirect)
		return
	}

	files := map[string]struct{ name, media string }{
		"/":                      {"https-setup.html", "text/html; charset=utf-8"},
		"/assets/https-setup.js": {"https-setup.js", "text/javascript; charset=utf-8"},
		"/assets/styles.css":     {"styles.css", "text/css; charset=utf-8"},
	}
	file, ok := files[r.URL.Path]
	if !ok {
		replyError(w, http.StatusForbidden, setupOnly)
		return
	}

	body, err := fs.ReadFile(server.assets, file.name)
	if err != nil {
		replyError(w, http.StatusServiceUnavailable, "HTTPS-Einrichtung ist nicht verfügbar")
		return
	}
	w.Header().Set("Content-Type", file.media)
	w.Write(body)
}

func (server *setup) challenge(w http.ResponseWriter, r *http.Request) {
	failure := func() { replyError(w, http.StatusNotFound, "Keine aktive ACME-Challenge") }
	if !challengeToken.MatchString(strings.TrimPrefix(r.URL.Path, challengePrefix)) {
		failure()
		return
	}

	address := url.URL{Scheme: "http", Host: "127.0.0.1:8080", Path: r.URL.Path}
	request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, address.String(), nil)
	if err != nil {
		failure()
		return
	}
	request.Host = r.Host
	response, err := server.client.Do(request)
	if err != nil {
		failure()
		return
	}
	defer response.Body.Close()

	if response.StatusCode >= 300 && response.StatusCode < 400 {
		failure()
		return
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxChallenge+1))
	if err != nil || len(body) > maxChallenge {
		failure()
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(response.StatusCode)
	w.Write(body)
}

func (server *setup) configure(w http.ResponseWriter, r *http.Request, snapshot config.Snapshot) {
	if r.URL.RequestURI() != "/api/https/configure" || snapshot.Phase == "configured" {
		replyError(w, http.StatusForbidden, setupOnly)
		return
	}

	contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	site := r.Header.Get("Sec-Fetch-Site")
	if contentType != "application/json" || site == "same-site" || site == "cross-site" ||
		r.Host == "" || r.Header.Get("Origin") != "http://"+r.Host {
		replyError(w, http.StatusForbidden, "Anfrage muss vom selben Origin stammen")
		return
	}

	matched, err := server.store.MatchesSetupCode(r.Header.Get("X-HTTPS-Setup-Code"), true)
	if err != nil || !matched {
		replyError(w, http.StatusForbidden, "Ungültiger HTTPS-Einrichtungscode")
		return
	}
	if r.ContentLength <= 0 || r.ContentLength > maxConfig {
		replyError(w, http.StatusBadRequest, "Ungültige Anfragelänge")
		return
	}

	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxConfig))
	var body config.Values
	if err != nil || json.Unmarshal(data, &body) != nil || body == nil {
		replyError(w, http.StatusBadRequest, "Ungültige HTTPS-Konfiguration")
		return
	}
	for key := range body {
		switch key {
		case "WEB_HOSTNAME", "ACME_CA_SERVER", "ACME_CA_CERTIFICATES_PEM":
		default:
			replyError(w, http.StatusBadRequest, "Nur HTTPS-Hostname, ACME-Adresse und CA-Zertifikat sind zulässig")
			return
		}
		if _, err := config.Validate(key, body[key]); err != nil {
			replyError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if strings.TrimSpace(body.String("WEB_HOSTNAME")) == "" || strings.TrimSpace(body.String("ACME_CA_SERVER")) == "" {
		replyError(w, http.StatusBadRequest, "HTTPS-Hostname und ACME-Adresse sind erforderlich")
		return
	}
	body["WEB_TLS_MODE"] = "acme"

	server.mu.Lock()
	defer server.mu.Unlock()
	environment, err := server.store.Environment(snapshot, false)
	if err != nil {
		replyError(w, http.StatusServiceUnavailable, "HTTPS-Konfiguration ist nicht verfügbar")
		return
	}
	if err := server.store.Save(r.Context(), body, snapshot.Revision, true); err != nil {
		if errors.Is(err, config.ErrConflict) {
			replyError(w, http.StatusConflict, "Konfiguration wurde inzwischen geändert")
		} else {
			replyError(w, http.StatusBadRequest, "HTTPS-Konfiguration konnte nicht gespeichert werden")
		}
		return
	}

	if err := securefile.WritePrivate(BootstrapMarker(environment["WEB_TLS_CERT_FILE"]), []byte("1")); err != nil {
		replyError(w, http.StatusServiceUnavailable, "ACME-Wiederholung konnte nicht vorbereitet werden")
		return
	}
	if err := WriteStatus(server.store.Root(), Status{State: "pending", Message: "ACME-Zertifikat wird angefordert"}); err != nil {
		replyError(w, http.StatusServiceUnavailable, "ACME-Status konnte nicht gespeichert werden")
		return
	}
	replyJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
}

func replyError(w http.ResponseWriter, status int, message string) {
	replyJSON(w, status, map[string]string{"error": message})
}

func replyJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}
