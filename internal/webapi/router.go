package webapi

import (
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/stuck-lehnert/domainshare/internal/config"
)

type Router struct {
	Store           *config.Store
	RunRoot         string
	Assets          fs.FS
	ServiceRevision int64
	Bootstrap       BootstrapAPI
	Session         SessionAPI
	Agent           AgentAPI
	AgentAdmin      AgentAdmin
	Documents       DocumentAPI
	Admin           http.Handler
}

func (router Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w.Header(), false, "no-store")
	if r.TLS == nil {
		writeError(w, http.StatusForbidden, "HTTPS erforderlich")
		return
	}

	uri := r.URL.EscapedPath()
	if strings.HasPrefix(uri, "/api/bootstrap/") {
		router.Bootstrap.ServeHTTP(w, r)
		return
	}
	snapshot, err := router.Store.Snapshot(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Konfiguration ist nicht verfügbar")
		return
	}

	configured := snapshot.Phase == "configured"
	current := snapshot.ServiceRevision == router.ServiceRevision
	if uri == "/healthz" && r.Method == http.MethodGet {
		if configured && (!current || !router.ready()) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "starting", "message": "Dateidienste werden gestartet"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}

	if strings.HasPrefix(uri, "/api/") || strings.HasPrefix(uri, "/admin/api/") {
		if !configured || !current || !router.ready() {
			message := "Dateidienste werden gestartet"
			if !configured {
				message = "Ersteinrichtung erforderlich"
			}
			writeError(w, http.StatusServiceUnavailable, message)
			return
		}
		router.routeAPI(w, r, uri)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, http.StatusMethodNotAllowed, "Statische Dateien sind nur lesbar")
		return
	}
	if !configured && !strings.HasPrefix(uri, "/assets/") {
		uri = "/setup"
	}
	router.serveAsset(w, r, uri)
}

func (router Router) ready() bool {
	info, err := os.Stat(filepath.Join(router.RunRoot, "domainshare-services-ready"))
	return err == nil && info.Mode().IsRegular()
}

func (router Router) routeAPI(w http.ResponseWriter, r *http.Request, uri string) {
	switch {
	case uri == "/api/login", uri == "/api/logout", uri == "/api/session", uri == "/admin/api/session":
		router.Session.ServeHTTP(w, r)
	case strings.HasPrefix(uri, "/api/agent/"):
		router.Agent.ServeHTTP(w, r)
	case uri == agentAdminPath || strings.HasPrefix(uri, agentAdminPath+"/"):
		router.AgentAdmin.ServeHTTP(w, r)
	case uri == "/api/documents" || strings.HasPrefix(uri, "/api/documents/"):
		router.Documents.ServeHTTP(w, r)
	case strings.HasPrefix(uri, "/admin/api/") && router.Admin != nil:
		router.Admin.ServeHTTP(w, r)
	default:
		writeError(w, http.StatusNotFound, "Nicht gefunden")
	}
}

const immutable = "public, max-age=31536000, immutable"
const pdfPrefix = "/assets/vendor/pdfjs/6.3.289-app1/"

type asset struct{ name, media string }

var assets = map[string]asset{
	"/setup":                                        {"setup.html", "text/html; charset=utf-8"},
	"/assets/setup.js":                              {"setup.js", "text/javascript; charset=utf-8"},
	"/assets/settings.js":                           {"settings.js", "text/javascript; charset=utf-8"},
	"/assets/portal.js":                             {"portal.js", "text/javascript; charset=utf-8"},
	"/assets/pdf-viewer.js":                         {"pdf-viewer.js", "text/javascript; charset=utf-8"},
	"/assets/pdf-viewer.css":                        {"pdf-viewer.css", "text/css; charset=utf-8"},
	"/assets/app.js":                                {"app.js", "text/javascript; charset=utf-8"},
	"/assets/report.mjs":                            {"report.mjs", "text/javascript; charset=utf-8"},
	"/assets/styles.css":                            {"styles.css", "text/css; charset=utf-8"},
	"/assets/vendor/typst/0.6.0-csp1/typst.mjs":     {"vendor/typst/typst.mjs", "text/javascript; charset=utf-8"},
	"/assets/vendor/typst/0.6.0-csp1/compiler.wasm": {"vendor/typst/compiler.wasm", "application/wasm"},
	"/assets/vendor/typst/0.6.0-csp1/LibertinusSerif-Regular.otf":  {"vendor/typst/LibertinusSerif-Regular.otf", "font/otf"},
	"/assets/vendor/typst/0.6.0-csp1/LibertinusSerif-Semibold.otf": {"vendor/typst/LibertinusSerif-Semibold.otf", "font/otf"},
}

var legacyPages = map[string]string{
	"/overview": "/overview", "/access": "/access", "/reconciliation": "/reconciliation",
	"/storage/data": "/storage/data", "/storage/users": "/storage/users", "/activity": "/activity",
	"/activity/fslogix": "/activity/fslogix", "/trash": "/trash", "/backup": "/backup",
	"/report": "/report", "/system": "/system", "/shares": "/access",
}

var pdfTypes = map[string]string{
	".html": "text/html; charset=utf-8", ".mjs": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
	".svg": "image/svg+xml", ".png": "image/png", ".json": "application/json", ".ftl": "text/plain; charset=utf-8",
	".wasm": "application/wasm", ".ttf": "font/ttf", ".woff": "font/woff", ".woff2": "font/woff2",
}

func (router Router) serveAsset(w http.ResponseWriter, r *http.Request, uri string) {
	if route, ok := legacyPages[uri]; ok {
		w.Header().Set("Location", "/admin"+route)
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusTemporaryRedirect)
		return
	}

	file, known := assets[uri]
	cache, pdfViewer := "no-store", false
	switch {
	case known && strings.HasPrefix(uri, "/assets/vendor/typst/"):
		cache = immutable
	case known:
	case strings.HasPrefix(uri, pdfPrefix):
		relative := strings.TrimPrefix(r.URL.Path, pdfPrefix)
		if !strings.HasPrefix(r.URL.Path, pdfPrefix) || !fs.ValidPath(relative) || relative == "." || strings.ContainsAny(relative, "\\\x00") {
			writeError(w, http.StatusNotFound, "Statische Datei nicht gefunden")
			return
		}
		media := pdfTypes[path.Ext(relative)]
		if media == "" {
			media = "application/octet-stream"
		}
		file = asset{"vendor/pdfjs/6.3.289-app1/" + relative, media}
		cache, pdfViewer = immutable, relative == "web/viewer.html"
	case strings.HasPrefix(uri, "/assets/"):
		writeError(w, http.StatusNotFound, "Statische Datei nicht gefunden")
		return
	case uri == "/admin" || strings.HasPrefix(uri, "/admin/"):
		file = asset{"index.html", "text/html; charset=utf-8"}
	default:
		file = asset{"portal.html", "text/html; charset=utf-8"}
	}

	body, err := fs.ReadFile(router.Assets, file.name)
	if err != nil {
		writeError(w, http.StatusNotFound, "Statische Datei nicht gefunden")
		return
	}
	setSecurityHeaders(w.Header(), pdfViewer, cache)
	w.Header().Set("Content-Type", file.media)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(body)
	}
}
