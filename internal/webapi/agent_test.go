package webapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stuck-lehnert/domainshare/internal/agenttoken"
	"github.com/stuck-lehnert/domainshare/internal/directory"
	"github.com/stuck-lehnert/domainshare/internal/documents"
	"github.com/stuck-lehnert/domainshare/internal/state"
	"github.com/stuck-lehnert/domainshare/internal/webauth"
)

const (
	userSID   = "S-1-5-21-1-2-3-1001"
	adminSID  = "S-1-5-21-1-2-3-1002"
	futureSID = "S-1-5-21-1-2-3-1003"
)

type fixtureDirectory struct {
	enabled atomic.Bool
	future  atomic.Bool
}

func (ad *fixtureDirectory) AccountLogin(user string) (string, error) {
	return (directory.Client{Getenv: func(string) string { return "AD" }}).AccountLogin(user)
}

func (ad *fixtureDirectory) ResolveAccount(_ context.Context, sam string) (string, error) {
	switch strings.ToLower(sam) {
	case "alice", "alice@ad.example", "ally@people.example":
		if ad.enabled.Load() {
			return userSID, nil
		}
	case "administrator":
		return adminSID, nil
	case "future":
		if ad.future.Load() {
			return futureSID, nil
		}
	}
	return "", directory.ErrAccount
}

func (*fixtureDirectory) CurrentIdentity(_ context.Context, sid string) (directory.Identity, error) {
	role, username := "user", `AD\alice`
	switch sid {
	case adminSID:
		role, username = "domain-admin", `AD\administrator`
	case futureSID:
		username = `AD\future`
	}
	return directory.Identity{SID: sid, Username: username, Role: role}, nil
}

func setupAgent(t *testing.T) (AgentAPI, *fixtureDirectory, func()) {
	t.Helper()
	root := t.TempDir()
	tokens, err := agenttoken.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tokens.Close() })

	policy, err := state.OpenPrivate(t.Context(), filepath.Join(root, "shares.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { policy.Close() })
	catalog, err := state.OpenPrivate(t.Context(), filepath.Join(root, "search.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { catalog.Close() })

	data := filepath.Join(root, "data")
	share := filepath.Join(data, "Reports")
	if err := os.MkdirAll(share, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(share, "Q3 überblick.pdf"), []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(share, "link")); err != nil {
		t.Fatal(err)
	}

	_, err = policy.Exec(`CREATE TABLE shares(objectGUID TEXT, shareName TEXT, path TEXT, isActive INTEGER);
		CREATE TABLE folder_permissions(folderId TEXT,kind TEXT,principalId TEXT,level INTEGER);
		CREATE TABLE access_users(sid TEXT,sam TEXT);`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Exec(`INSERT INTO shares VALUES('reports','Reports',?,1)`, share); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Exec(`INSERT INTO folder_permissions VALUES('reports','user',?,1)`, userSID); err != nil {
		t.Fatal(err)
	}
	_, err = catalog.Exec(`CREATE TABLE document_sources(id TEXT,kind TEXT,label TEXT,root TEXT,owner_sid TEXT)`)
	if err != nil {
		t.Fatal(err)
	}

	ad := &fixtureDirectory{}
	ad.enabled.Store(true)
	api := AgentAPI{Tokens: tokens, Accounts: ad, Files: documents.Service{Policy: policy, Catalog: catalog, DataRoot: data}}
	return api, ad, func() {
		if _, err := policy.Exec(`UPDATE folder_permissions SET level=0`); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLiveAgentTLS(t *testing.T) {
	api, ad, revokeShare := setupAgent(t)
	issued, err := api.Tokens.Issue(t.Context(), "Fixture", map[string]string{userSID: "stale-display-name"}, 1, "admin")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := api.Tokens.Issue(t.Context(), "Admin Fixture", map[string]string{adminSID: "administrator"}, 1, "admin")
	if err != nil {
		t.Fatal(err)
	}
	var log strings.Builder
	api.Logger = slog.New(slog.NewTextHandler(&log, nil))
	api.Indexed = func(w http.ResponseWriter, _ *http.Request, path string, query url.Values, id directory.Identity) {
		writeJSON(w, http.StatusOK, map[string]string{"path": path, "sid": id.SID, "q": query.Get("q")})
	}
	server := httptest.NewTLSServer(api)
	t.Cleanup(server.Close)

	request := func(method, target, token string, duplicate bool, byteRange string) (int, http.Header, string) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), method, server.URL+target, nil)
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if duplicate {
			req.Header.Add("Authorization", "Bearer "+token)
		}
		if byteRange != "" {
			req.Header.Set("Range", byteRange)
		}
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, resp.Header, string(body)
	}

	const list = agentPrefix + "/list"
	for _, tc := range []struct {
		method, target, token string
		duplicate             bool
		status                int
	}{
		{"GET", list + "?username=alice", "", false, 401},
		{"GET", list + "?username=alice", issued.Raw, true, 401},
		{"GET", list, issued.Raw, false, 400},
		{"GET", list + "?username=alice&user%6eame=administrator", issued.Raw, false, 400},
		{"GET", list + "?username=%FF", issued.Raw, false, 400},
		{"GET", list + "?username=administrator", issued.Raw, false, 403},
		{"GET", list + "?username=alice@unknown.example", issued.Raw, false, 403},
		{"GET", list + "?username=alice" + strings.Repeat("&a=1", 24), issued.Raw, false, 400},
		{"GET", agentPrefix + "/%6cist?username=alice", issued.Raw, false, 404},
		{"POST", list + "?username=alice", issued.Raw, false, 405},
	} {
		code, _, body := request(tc.method, tc.target, tc.token, tc.duplicate, "")
		if code != tc.status {
			t.Fatalf("%s %s: status %d, want %d: %s", tc.method, tc.target, code, tc.status, body)
		}
	}

	code, headers, body := request("GET", list+"?username=AD%5Calice", issued.Raw, false, "")
	if code != 200 || !strings.Contains(body, "data:reports") || headers.Get("Cache-Control") != "no-store" {
		t.Fatalf("source listing: %d %q", code, body)
	}
	for _, alias := range []string{"alice@AD.EXAMPLE", "Ally@people.example"} {
		code, _, aliased := request("GET", list+"?username="+url.QueryEscape(alias), issued.Raw, false, "")
		if code != 200 || aliased != body {
			t.Fatalf("alias %q resolved to different sources: %d %q", alias, code, aliased)
		}
	}

	code, _, body = request("GET", list+"?username=alice&source=data:reports&limit=1", issued.Raw, false, "")
	if code != 200 || !strings.Contains(body, "Q3 überblick.pdf") || strings.Contains(body, `"link"`) {
		t.Fatalf("folder listing: %d %q", code, body)
	}
	code, _, body = request("GET", agentPrefix+"/search?username=alice&q=hello;private", issued.Raw, false, "")
	if code != 200 || !strings.Contains(body, "/api/documents") || !strings.Contains(body, userSID) || !strings.Contains(body, "hello;private") {
		t.Fatalf("authorized search handoff: %d %q", code, body)
	}

	file := agentPrefix + "/file?source=data:reports&path=" + url.QueryEscape("Q3 überblick.pdf")
	code, headers, body = request("GET", file+"&username=alice", issued.Raw, false, "bytes=2-5")
	if code != 206 || headers.Get("Content-Range") != "bytes 2-5/10" || body != "2345" ||
		headers.Get("Content-Disposition") != "attachment; filename*=UTF-8''Q3%20%C3%BCberblick.pdf" {
		t.Fatalf("file range: code=%d headers=%v body=%q", code, headers, body)
	}
	code, headers, body = request("GET", file+"&username=alice", issued.Raw, false, "bytes=2-5,8-9")
	if code != 416 || headers.Get("Content-Range") != "bytes */10" || body != "" {
		t.Fatalf("multiple ranges accepted: code=%d headers=%v body=%q", code, headers, body)
	}
	code, _, _ = request("GET", agentPrefix+"/file?username=alice&source=data:reports&path=link", issued.Raw, false, "")
	if code != 404 {
		t.Fatalf("symlink resolved: status %d", code)
	}

	revokeShare()
	code, _, _ = request("GET", file+"&username=alice", issued.Raw, false, "")
	if code != 404 {
		t.Fatalf("share revocation ignored: %d", code)
	}
	code, _, body = request("GET", file+"&username=administrator", admin.Raw, false, "")
	if code != 200 || body != "0123456789" {
		t.Fatalf("administrator lost Data access: %d %q", code, body)
	}
	ad.enabled.Store(false)
	code, _, _ = request("GET", list+"?username=alice", issued.Raw, false, "")
	if code != 403 {
		t.Fatalf("disabled directory account used: %d", code)
	}
	if strings.Contains(log.String(), issued.Raw) || strings.Contains(log.String(), admin.Raw) || strings.Contains(log.String(), "hello;private") {
		t.Fatal("private credential or query leaked in log")
	}
}

func TestAgentManagementRequiresAdminAndCSRF(t *testing.T) {
	api, ad, _ := setupAgent(t)
	db, err := state.OpenPrivate(t.Context(), filepath.Join(t.TempDir(), "shares.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	sessions, err := webauth.New(t.Context(), db, "synthetic-admin-and-user-session-fixture", time.Hour, time.Minute, ad.CurrentIdentity)
	if err != nil {
		t.Fatal(err)
	}
	origins, err := webauth.NewOrigins("https://files.ad.test")
	if err != nil {
		t.Fatal(err)
	}
	admin := AgentAdmin{Auth: SessionAPI{Origins: origins, Sessions: sessions}, API: api}
	issueSession := func(sid string) (string, string) {
		t.Helper()
		id, err := ad.CurrentIdentity(t.Context(), sid)
		if err != nil {
			t.Fatal(err)
		}
		token, s, err := sessions.Issue(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		return token, sessions.CSRF(s)
	}
	token, csrf := issueSession(adminSID)
	user, userCSRF := issueSession(userSID)
	request := func(method, path, token, csrf, origin, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, "https://files.ad.test"+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-CSRF-Token", csrf)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		admin.ServeHTTP(response, req)
		return response
	}

	const grant = `{"label":"Automatisierung","usernames":["alice"],"expiresInDays":30}`
	const grantAll = `{"label":"Alle Konten","usernames":[]}`
	for _, tc := range []struct {
		token, csrf, origin, body string
		status                    int
	}{
		{user, userCSRF, "", grant, 403},
		{user, userCSRF, "", grantAll, 403},
		{token, "", "", grant, 403},
		{token, csrf, "https://evil.test", grant, 403},
		{token, csrf, "https://files.ad.test", `{"label":"Null","usernames":["alice"],"expiresInDays":null}`, 400},
		{token, csrf, "https://files.ad.test", `{"label":"Missing usernames"}`, 400},
		{token, csrf, "https://files.ad.test", `{"label":"Null usernames","usernames":null}`, 400},
		{token, csrf, "https://files.ad.test", `{"label":"Invalid username","usernames":[null]}`, 400},
	} {
		response := request("POST", agentAdminPath, tc.token, tc.csrf, tc.origin, tc.body)
		if response.Code != tc.status {
			t.Fatalf("token grant status %d, want %d: %s", response.Code, tc.status, response.Body)
		}
	}
	response := request("POST", agentAdminPath, token, csrf, "https://files.ad.test", grant)
	var issued agenttoken.Issued
	if response.Code != 201 || json.Unmarshal(response.Body.Bytes(), &issued) != nil || issued.Raw == "" {
		t.Fatalf("grant status %d: %s", response.Code, response.Body)
	}
	response = request("GET", agentAdminPath, token, "", "", "")
	if response.Code != 200 || !strings.Contains(response.Body.String(), issued.ID) || strings.Contains(response.Body.String(), issued.Raw) {
		t.Fatal("inventory does not reveal only metadata")
	}
	if response = request("GET", agentAdminPath, issued.Raw, "", "", ""); response.Code != 401 {
		t.Fatalf("agent credential accepted as admin session: %d", response.Code)
	}

	response = request("POST", agentAdminPath, token, csrf, "https://files.ad.test", grantAll)
	var all agenttoken.Issued
	if response.Code != 201 || json.Unmarshal(response.Body.Bytes(), &all) != nil || all.Raw == "" {
		t.Fatalf("grant all-user scope: HTTP %d", response.Code)
	}
	response = request("GET", agentAdminPath, token, "", "", "")
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"allUsers":true`) || strings.Contains(response.Body.String(), all.Raw) {
		t.Fatal("inventory did not show the all-user scope safely")
	}

	list := func(credential, query string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "https://files.ad.test"+agentPrefix+"/list"+query, nil)
		req.Header.Set("Authorization", "Bearer "+credential)
		res := httptest.NewRecorder()
		api.ServeHTTP(res, req)
		return res
	}
	if res := list(all.Raw, ""); res.Code != 400 {
		t.Fatalf("all-user scope accepted a request without username: HTTP %d", res.Code)
	}
	if res := list(all.Raw, "?username=future"); res.Code != 403 {
		t.Fatalf("unknown account was not rejected: HTTP %d", res.Code)
	}
	ad.future.Store(true)
	if res := list(all.Raw, "?username=future"); res.Code != 200 || strings.Contains(res.Body.String(), "data:reports") {
		t.Fatalf("future account was not included with only its own rights: HTTP %d, %s", res.Code, res.Body)
	}
	if res := list(issued.Raw, "?username=future"); res.Code != 403 {
		t.Fatalf("restricted token scope was broadened: HTTP %d", res.Code)
	}
	if res := list(all.Raw, "?username=administrator"); res.Code != 200 || !strings.Contains(res.Body.String(), "data:reports") {
		t.Fatalf("all-user scope did not cover current administrator rights: HTTP %d, %s", res.Code, res.Body)
	}
	ad.enabled.Store(false)
	if res := list(all.Raw, "?username=alice"); res.Code != 403 {
		t.Fatalf("all-user scope accepted a disabled account: HTTP %d", res.Code)
	}
	if res := request("POST", agentAdminPath+"/revoke", token, csrf, "", `{"id":"`+all.ID+`"}`); res.Code != 200 {
		t.Fatalf("revoking the all-user token returned HTTP %d", res.Code)
	}
	if res := list(all.Raw, "?username=future"); res.Code != 401 {
		t.Fatalf("revoked all-user token was accepted: HTTP %d", res.Code)
	}

	response = request("POST", agentAdminPath+"/revoke", token, csrf, "", `{"id":"`+issued.ID+`"}`)
	if response.Code != 200 {
		t.Fatalf("revoke status %d: %s", response.Code, response.Body)
	}
	if _, err := api.Tokens.Authenticate(t.Context(), issued.Raw); !errors.Is(err, agenttoken.ErrInvalid) {
		t.Fatalf("revocation not effective: %v", err)
	}
}
