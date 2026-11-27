package webapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stuck-lehnert/domainshare/internal/documents"
	"github.com/stuck-lehnert/domainshare/internal/webauth"
	"golang.org/x/sys/unix"
)

func TestSearchResultPDFBytes(t *testing.T) {
	agent, ad, revokeShare := setupAgent(t)
	ctx := t.Context()
	root := filepath.Join(agent.Files.DataRoot, "Reports")
	catalog, err := documents.OpenCatalog(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer catalog.Close()
	agent.Files.Catalog = catalog
	if _, err := catalog.ExecContext(ctx, `INSERT INTO document_sources(id,kind,label,root) VALUES('data:reports','data','Reports',?)`, root); err != nil {
		t.Fatal(err)
	}

	const pdfID = "00112233445566778899aabbccddeeff"
	const textID = "ffeeddccbbaa99887766554433221100"
	const pdf = "%PDF-1.7\n% original file bytes\n"
	for _, file := range []struct{ id, name, extension, content string }{
		{pdfID, "Report.pdf", ".pdf", pdf},
		{textID, "Notes.txt", ".txt", "Plain text file"},
	} {
		path := filepath.Join(root, file.name)
		if err := os.WriteFile(path, []byte(file.content), 0o600); err != nil {
			t.Fatal(err)
		}
		var st unix.Stat_t
		if err := unix.Stat(path, &st); err != nil {
			t.Fatal(err)
		}
		fingerprint := fmt.Sprintf("%d:%d:%d:%d:%d", st.Dev, st.Ino, st.Size, st.Mtim.Nano(), st.Ctim.Nano())
		if _, err := catalog.ExecContext(ctx, `INSERT INTO documents(id,source_id,path,name,extension,size,modified,fingerprint)
			VALUES(?,'data:reports',?,?,?,?,?,?)`, file.id, file.name, file.name, file.extension, st.Size, st.Mtim.Sec, fingerprint); err != nil {
			t.Fatal(err)
		}
	}

	sessions, err := webauth.New(ctx, agent.Files.Policy, "synthetic-test-session-key-not-used-in-production", time.Hour, time.Minute, ad.CurrentIdentity)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := ad.CurrentIdentity(ctx, userSID)
	if err != nil {
		t.Fatal(err)
	}
	browserToken, _, err := sessions.Issue(ctx, identity)
	if err != nil {
		t.Fatal(err)
	}
	agentToken, err := agent.Tokens.Issue(ctx, "PDF fixture", map[string]string{userSID: "alice"}, 1, "admin")
	if err != nil {
		t.Fatal(err)
	}

	api := DocumentAPI{Files: agent.Files, Sessions: SessionAPI{Sessions: sessions}}
	agent.Indexed = api.ServeIdentity

	request := func(asAgent bool, path, byteRange string) *httptest.ResponseRecorder {
		t.Helper()
		handler := http.Handler(api)
		prefix := "/api"
		if asAgent {
			handler, prefix = agent, agentPrefix
			separator := "?"
			if strings.Contains(path, "?") {
				separator = "&"
			}
			path += separator + "username=alice"
		}
		req := httptest.NewRequest("GET", "https://files.example.test"+prefix+path, nil)
		if asAgent {
			req.Header.Set("Authorization", "Bearer "+agentToken.Raw)
		} else {
			req.AddCookie(&http.Cookie{Name: webauth.CookieName, Value: browserToken})
		}
		if byteRange != "" {
			req.Header.Set("Range", byteRange)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}

	for _, asAgent := range []bool{false, true} {
		name, searchPath := "browser", "/documents"
		if asAgent {
			name, searchPath = "agent", "/search"
		}
		t.Run(name, func(t *testing.T) {
			result := request(asAgent, searchPath+"?scope=name&q=Report.pdf", "")
			var found documents.SearchResult
			if result.Code != 200 || json.Unmarshal(result.Body.Bytes(), &found) != nil || len(found.Items) != 1 ||
				found.Items[0].ID != pdfID || found.Items[0].Extension != "pdf" {
				t.Fatalf("search did not return the expected PDF: HTTP %d, %s", result.Code, result.Body)
			}
			path := "/documents/" + found.Items[0].ID
			content := request(asAgent, path+"/content", "")
			if content.Code != 200 || content.Header().Get("Content-Type") != "application/pdf" || content.Body.String() != pdf {
				t.Fatalf("PDF content: HTTP %d, %s", content.Code, content.Body)
			}

			part := request(asAgent, path+"/content", "bytes=0-4")
			if part.Code != 206 || part.Body.String() != "%PDF-" || part.Header().Get("Content-Range") != fmt.Sprintf("bytes 0-4/%d", len(pdf)) {
				t.Fatalf("PDF byte range: HTTP %d, %s", part.Code, part.Body)
			}
			download := request(asAgent, path+"/download", "")
			if download.Code != 200 || download.Body.String() != pdf || !strings.HasPrefix(download.Header().Get("Content-Disposition"), "attachment;") {
				t.Fatalf("download original: HTTP %d", download.Code)
			}
			if out := request(asAgent, "/documents/"+textID+"/content", ""); out.Code != 404 {
				t.Fatalf("non-PDF was served inline: HTTP %d", out.Code)
			}
		})
	}

	revokeShare()
	for _, asAgent := range []bool{false, true} {
		if out := request(asAgent, "/documents/"+pdfID+"/content", "bytes=0-4"); out.Code != 404 {
			t.Fatalf("PDF remained accessible after revoking permissions (agent=%v): HTTP %d", asAgent, out.Code)
		}
	}
}
