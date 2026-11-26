package health

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckRequiresHTTPSHealthzWithStatusOK(t *testing.T) {
	for _, test := range []struct {
		name string
		code int
	}{
		{"healthy", http.StatusOK},
		{"unavailable", http.StatusServiceUnavailable},
		{"no redirects", http.StatusTemporaryRedirect},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/healthz" || r.Method != http.MethodGet {
					t.Errorf("unexpected probe: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusOK)
					return
				}
				w.Header().Set("Location", "/not-healthz")
				w.WriteHeader(test.code)
			}))
			t.Cleanup(server.Close)
			err := Check(t.Context(), server.Listener.Addr().(*net.TCPAddr).Port)
			if (err == nil) != (test.code == http.StatusOK) {
				t.Fatalf("check for HTTP %d: %v", test.code, err)
			}
		})
	}
}
