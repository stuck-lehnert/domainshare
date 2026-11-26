package webapi

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stuck-lehnert/domainshare/internal/config"
	"github.com/stuck-lehnert/domainshare/internal/tlssetup"
)

func TestHTTPSBootstrapAndCertificateReload(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	root := t.TempDir()
	store, err := config.Open(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := tlssetup.Prepare(ctx, store); err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(root, "tls", "web.crt"), filepath.Join(root, "tls", "web.key")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	assets := fstest.MapFS{"setup.html": {Data: []byte("test setup")}}
	router := Router{Store: store, Assets: assets, RunRoot: t.TempDir()}
	done := make(chan error, 1)
	go func() { done <- serveHTTPS(ctx, listener, certPath, keyPath, router) }()

	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	request := func(path string, status int) string {
		t.Helper()
		res, err := client.Get("https://" + listener.Addr().String() + path)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != status {
			t.Fatalf("%s returned %d, expected %d", path, res.StatusCode, status)
		}
		return res.TLS.PeerCertificates[0].SerialNumber.String()
	}
	initial := request("/healthz", http.StatusOK)
	request("/", http.StatusOK)
	request("/api/session", http.StatusServiceUnavailable)

	otherRoot := t.TempDir()
	other, err := config.Open(ctx, otherRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := tlssetup.Prepare(ctx, other); err != nil {
		t.Fatal(err)
	}
	copyFile := func(name, path string) {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(otherRoot, "tls", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	copyFile("web.crt", certPath)
	time.Sleep(1100 * time.Millisecond)
	if serial := request("/healthz", http.StatusOK); serial != initial {
		t.Fatal("server used a mismatched keypair")
	}
	copyFile("web.key", keyPath)
	time.Sleep(1100 * time.Millisecond)
	if serial := request("/healthz", http.StatusOK); serial == initial {
		t.Fatal("server did not load renewed keypair")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("HTTPS server did not shut down")
	}
}
