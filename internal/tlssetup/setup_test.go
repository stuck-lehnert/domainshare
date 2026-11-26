package tlssetup

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stuck-lehnert/domainshare/internal/config"
)

func openStore(t *testing.T) *config.Store {
	t.Helper()
	store, err := config.Open(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestHTTPSetupBoundaries(t *testing.T) {
	store := openStore(t)
	code, err := store.SetupCode(true)
	if err != nil {
		t.Fatal(err)
	}
	handler := HTTPHandler(store, fstest.MapFS{})

	const good = `{"WEB_HOSTNAME":"share.example.test","ACME_CA_SERVER":"https://ca.example.test/acme"}`
	for _, test := range []struct {
		name, path, origin, code, site, payload string
		want                                    int
	}{
		{"login blocked", "/api/login", "", "", "", "", http.StatusForbidden},
		{"cross-origin", "/api/https/configure", "http://elsewhere.example.test", code, "", good, http.StatusForbidden},
		{"same-site", "/api/https/configure", "http://setup.example.test", code, "same-site", good, http.StatusForbidden},
		{"wrong code", "/api/https/configure", "http://setup.example.test", "wrong", "", good, http.StatusForbidden},
		{"other field", "/api/https/configure", "http://setup.example.test", code, "", `{"JOIN_PASSWORD":"not-accepted-over-http"}`, http.StatusBadRequest},
		{"URL credentials", "/api/https/configure", "http://setup.example.test", code, "", `{"WEB_HOSTNAME":"share.example.test","ACME_CA_SERVER":"https://name:secret@ca.example.test/acme"}`, http.StatusBadRequest},
		{"oversized", "/api/https/configure", "http://setup.example.test", code, "", strings.Repeat(" ", maxConfig+1), http.StatusBadRequest},
		{"valid", "/api/https/configure", "http://setup.example.test", code, "same-origin", good, http.StatusAccepted},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "http://setup.example.test"+test.path, strings.NewReader(test.payload))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Origin", test.origin)
			request.Header.Set("X-HTTPS-Setup-Code", test.code)
			request.Header.Set("Sec-Fetch-Site", test.site)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			if response.Code != test.want || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("unexpected response: %d %s", response.Code, response.Body.String())
			}
		})
	}

	snap, err := store.Snapshot(t.Context())
	if err != nil || snap.Values.String("WEB_TLS_MODE") != "acme" || snap.Revision != 1 {
		t.Fatalf("expected one update: revision=%d err=%v", snap.Revision, err)
	}
	if ReadStatus(store.Root()).State != "pending" {
		t.Fatal("missing ACME status")
	}
}

func TestConfiguredRedirectDoesNotUseRequestHost(t *testing.T) {
	store := openStore(t)
	imported, err := store.ImportLegacy(t.Context(), map[string]string{
		"REALM": "EXAMPLE.TEST", "WORKGROUP": "EXAMPLE", "DOMAIN": "example.test",
		"DOMAIN_USERS_SID": "S-1-5-21-1-513", "DOMAIN_ADMINS_SID": "S-1-5-21-1-512",
		"WEB_HOSTNAME": "share.example.test", "WEB_HTTPS_PORT": "8444",
	})
	if err != nil || !imported {
		t.Fatalf("legacy setup: %v, %v", imported, err)
	}

	request := httptest.NewRequest(http.MethodGet, "http://not-configured.example.test/path?key=value", nil)
	response := httptest.NewRecorder()
	HTTPHandler(store, fstest.MapFS{}).ServeHTTP(response, request)
	if response.Code != http.StatusPermanentRedirect || response.Header().Get("Location") != "https://share.example.test:8444/" {
		t.Fatalf("redirect status %d, location %q", response.Code, response.Header().Get("Location"))
	}
}

type transportFunc func(*http.Request) (*http.Response, error)

func (fn transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

func TestChallengeIsLocalAndDoesNotForwardCredentials(t *testing.T) {
	handler := HTTPHandler(openStore(t), fstest.MapFS{}).(*setup)
	handler.client.Transport = transportFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != "http://127.0.0.1:8080/.well-known/acme-challenge/sample_token" ||
			request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
			t.Fatal("challenge was not isolated from the request origin")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("proof"))}, nil
	})
	request := httptest.NewRequest(http.MethodGet, "http://share.example.test/.well-known/acme-challenge/sample_token?ignored=1", nil)
	request.Header.Set("Authorization", "Bearer not-forwarded")
	request.Header.Set("Cookie", "session=not-forwarded")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "proof" {
		t.Fatalf("challenge: %d %s", response.Code, response.Body.String())
	}
}

func TestBootstrapTLSReuseAndRotation(t *testing.T) {
	store := openStore(t)
	ctx := t.Context()
	first, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	env, err := store.Environment(first, false)
	if err != nil {
		t.Fatal(err)
	}
	cert, key := env["WEB_TLS_CERT_FILE"], env["WEB_TLS_KEY_FILE"]
	getCertificate := func() *x509.Certificate {
		t.Helper()
		if err := Prepare(ctx, store); err != nil {
			t.Fatal(err)
		}
		pair, err := tls.LoadX509KeyPair(cert, key)
		if err != nil || len(pair.Certificate) == 0 {
			t.Fatalf("invalid pair: %v", err)
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		return leaf
	}

	bootstrap := getCertificate()
	if err := bootstrap.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if mode, err := os.Stat(key); err != nil || mode.Mode().Perm() != 0o600 {
		t.Fatalf("bootstrap private key permissions: %v %v", mode, err)
	}
	if reused := getCertificate(); bootstrap.SerialNumber.Cmp(reused.SerialNumber) != 0 {
		t.Fatal("bootstrap certificate was needlessly recreated")
	}
	if err := store.Save(ctx, config.Values{"WEB_HOSTNAME": "share.example.test"}, first.Revision, true); err != nil {
		t.Fatal(err)
	}
	rotated := getCertificate()
	if err := rotated.VerifyHostname("share.example.test"); err != nil {
		t.Fatal(err)
	}
	if bootstrap.SerialNumber.Cmp(rotated.SerialNumber) == 0 {
		t.Fatal("bootstrap certificate was not rotated for a new hostname")
	}
}
