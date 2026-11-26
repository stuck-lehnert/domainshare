package webapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stuck-lehnert/domainshare/internal/config"
	"github.com/stuck-lehnert/domainshare/internal/directory"
	"github.com/stuck-lehnert/domainshare/internal/webauth"
)

const (
	setupAdminGroup = "S-1-5-21-1-2-3-512"
	setupUsersGroup = "S-1-5-21-1-2-3-513"
)

type setupDirectory struct {
	admin       bool
	beforeCheck func()
}

func (*setupDirectory) ListGroups(context.Context) ([]directory.Group, error) {
	return []directory.Group{{SID: setupAdminGroup, Name: "Administratoren"}, {SID: setupUsersGroup, Name: "Benutzer"}}, nil
}

func (*setupDirectory) Authenticate(_ context.Context, user, password string) (directory.Identity, error) {
	if user != "join" || password != "secret-join-password" {
		return directory.Identity{}, directory.ErrAccount
	}
	return directory.Identity{SID: "S-1-5-21-1-2-3-1101", Username: user, Role: "user"}, nil
}

func (client *setupDirectory) CurrentIdentityWithAdminSID(_ context.Context, sid, group string) (directory.Identity, error) {
	if client.beforeCheck != nil {
		client.beforeCheck()
	}
	if !client.admin || sid != "S-1-5-21-1-2-3-1101" || group != setupAdminGroup {
		return directory.Identity{SID: sid, Role: "user"}, nil
	}
	return directory.Identity{SID: sid, Username: "join", Role: "domain-admin"}, nil
}

func TestBootstrapAuthorizationAndAtomicConclusion(t *testing.T) {
	ctx := t.Context()
	store, err := config.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	code, err := store.SetupCode(false)
	if err != nil {
		t.Fatal(err)
	}
	origins, err := webauth.NewOrigins("https://share.example.test")
	if err != nil {
		t.Fatal(err)
	}
	ad := &setupDirectory{}
	api := BootstrapAPI{Store: store, RunRoot: t.TempDir(), Origins: func(config.Snapshot) webauth.Origins { return origins },
		Directory: func(config.Snapshot) BootstrapDirectory { return ad }}

	request := func(method, operation, body, origin string, codes ...string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://untrusted.example.test/api/bootstrap/"+operation, strings.NewReader(body))
		for _, value := range codes {
			r.Header.Add("X-Setup-Token", value)
		}
		r.Header.Set("Content-Type", "application/json")
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		api.ServeHTTP(w, r)
		return w
	}
	check := func(w *httptest.ResponseRecorder, status int) {
		t.Helper()
		if w.Code != status {
			t.Fatalf("got %d, want %d: %s", w.Code, status, w.Body)
		}
		if strings.Contains(w.Body.String(), "secret-join-password") {
			t.Fatal("join password leaked")
		}
	}
	const domain = `{"revision":0,"values":{"REALM":"EXAMPLE.TEST","WORKGROUP":"EXAMPLE","DOMAIN":"EXAMPLE","JOIN_USER":"join","JOIN_PASSWORD":"secret-join-password","WEB_HOSTNAME":"share.example.test"}}`
	check(request("GET", "status", "", ""), http.StatusOK)
	check(request("GET", "settings", "", ""), http.StatusForbidden)
	check(request("GET", "settings", "", "", code, code), http.StatusForbidden)
	check(request("POST", "domain", domain, "https://untrusted.example.test", code), http.StatusForbidden)
	check(request("POST", "domain", domain, "https://share.example.test", code), http.StatusAccepted)
	check(request("POST", "domain", domain, "https://share.example.test", code), http.StatusConflict)
	check(request("GET", "settings", "", "", code), http.StatusOK)
	check(request("GET", "groups", "", "", code), http.StatusBadRequest)

	marker := filepath.Join(api.RunRoot, "domainshare-domain-ready")
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvanceToGroups(ctx, 1); err != nil {
		t.Fatal(err)
	}
	check(request("GET", "groups", "", "", code), http.StatusOK)

	groups := map[string]string{"DOMAIN_USERS_SID": setupUsersGroup, "DOMAIN_ADMINS_SID": setupAdminGroup, "FSLOGIX_GROUP_SID": setupUsersGroup}
	finish := func(revision int64) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(map[string]any{"revision": revision, "values": groups})
		if err != nil {
			t.Fatal(err)
		}
		return request("POST", "finish", string(body), "https://share.example.test", code)
	}
	check(finish(2), http.StatusBadRequest)

	ad.admin = true
	ad.beforeCheck = func() {
		if err := store.SubmitDomain(ctx, config.Values{}, 2); err != nil {
			t.Fatal(err)
		}
	}
	check(finish(2), http.StatusConflict)
	snapshot, err := store.Snapshot(ctx)
	if err != nil || snapshot.Revision != 3 || snapshot.Phase != "joining" || snapshot.Values.String("DOMAIN_ADMINS_SID") != "" {
		t.Fatalf("racing submission partially saved groups: phase %q, revision %d, error %v", snapshot.Phase, snapshot.Revision, err)
	}

	ad.beforeCheck = nil
	if err := store.AdvanceToGroups(ctx, 3); err != nil {
		t.Fatal(err)
	}
	check(finish(4), http.StatusOK)
	check(request("GET", "settings", "", "", code), http.StatusForbidden)
	check(request("GET", "status", "", ""), http.StatusOK)
	snapshot, err = store.Snapshot(ctx)
	if err != nil || snapshot.Revision != 5 || snapshot.Phase != "configured" || snapshot.Values.String("DOMAIN_ADMINS_SID") != setupAdminGroup {
		t.Fatalf("groups and phase were not committed together: phase %q, revision %d, error %v", snapshot.Phase, snapshot.Revision, err)
	}
}
