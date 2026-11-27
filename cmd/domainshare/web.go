package main

import (
	"context"
	"database/sql"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/stuck-lehnert/domainshare/internal/agenttoken"
	"github.com/stuck-lehnert/domainshare/internal/audit"
	"github.com/stuck-lehnert/domainshare/internal/config"
	"github.com/stuck-lehnert/domainshare/internal/directory"
	"github.com/stuck-lehnert/domainshare/internal/documents"
	"github.com/stuck-lehnert/domainshare/internal/state"
	"github.com/stuck-lehnert/domainshare/internal/trash"
	"github.com/stuck-lehnert/domainshare/internal/webapi"
	"github.com/stuck-lehnert/domainshare/internal/webauth"
)

func setting(env map[string]string, key, fallback string) string {
	if value := env[key]; value != "" {
		return value
	}
	return fallback
}

func webOrigins(env map[string]string) (webauth.Origins, error) {
	if origins := strings.TrimSpace(env["WEB_TRUSTED_ORIGINS"]); origins != "" {
		return webauth.NewOrigins(origins)
	}

	host := setting(env, "WEB_HOSTNAME", "localhost")
	if port := setting(env, "WEB_HTTPS_PORT", "443"); port != "443" {
		host = net.JoinHostPort(host, port)
	}
	return webauth.NewOrigins((&url.URL{Scheme: "https", Host: host}).String())
}

func directoryClient(env map[string]string) directory.Client {
	return directory.Client{Getenv: func(key string) string { return env[key] }}
}

func runWeb(ctx context.Context, store *config.Store, address, assets, runRoot string) error {
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		return err
	}
	env, err := store.Environment(snapshot, false)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(assets)
	if err != nil {
		return err
	}
	defer root.Close()

	bootstrap := webapi.BootstrapAPI{
		Store: store, RunRoot: runRoot,
		Origins: func(s config.Snapshot) webauth.Origins {
			settings, err := store.Environment(s, false)
			if err != nil {
				return webauth.Origins{}
			}
			origins, _ := webOrigins(settings)
			return origins
		},
		Directory: func(s config.Snapshot) webapi.BootstrapDirectory {
			settings, err := store.Environment(s, false)
			if err != nil {
				return nil
			}
			return directoryClient(settings)
		},
	}
	router := webapi.Router{
		Store: store, RunRoot: runRoot, Assets: root.FS(),
		ServiceRevision: snapshot.ServiceRevision, Bootstrap: bootstrap,
	}

	if snapshot.Phase == "configured" {
		cleanup, err := configureWeb(ctx, store, snapshot, env, &router)
		if err != nil {
			return err
		}
		defer cleanup()
	}
	if address == "" {
		address = net.JoinHostPort(setting(env, "WEB_BIND_ADDRESS", "0.0.0.0"), env["WEB_BIND_PORT"])
	}
	return webapi.ServeHTTPS(ctx, address, env["WEB_TLS_CERT_FILE"], env["WEB_TLS_KEY_FILE"], router)
}

func configureWeb(ctx context.Context, store *config.Store, snapshot config.Snapshot, env map[string]string, router *webapi.Router) (func(), error) {
	var resources []func() error
	cleanup := func() {
		for i := len(resources) - 1; i >= 0; i-- {
			_ = resources[i]()
		}
	}
	ready := false
	defer func() {
		if !ready {
			cleanup()
		}
	}()

	policy, err := state.OpenPrivate(ctx, env["STATE_DB_PATH"])
	if err != nil {
		return nil, err
	}
	resources = append(resources, policy.Close)
	access, err := newAccess(policy, store.Root(), env, nil)
	if err != nil {
		return nil, err
	}
	if err := access.EnsureSchema(ctx); err != nil {
		return nil, err
	}
	audits, err := audit.NewStore(ctx, policy)
	if err != nil {
		return nil, err
	}
	recycle, err := trash.New(trash.OptionsFromEnv(func(key string) (string, bool) {
		value, ok := env[key]
		return value, ok
	}))
	if err != nil {
		return nil, err
	}

	client := directoryClient(env)
	ttl := time.Duration(snapshot.Values.Int("WEB_JWT_TTL_SECONDS")) * time.Second
	recheck := time.Duration(snapshot.Values.Int("WEB_AUTH_RECHECK_SECONDS")) * time.Second
	sessions, err := webauth.New(ctx, policy, snapshot.Values.String("WEB_JWT_SECRET"), ttl, recheck, client.CurrentIdentity)
	if err != nil {
		return nil, err
	}
	origins, err := webOrigins(env)
	if err != nil {
		return nil, err
	}
	apiTokens, err := agenttoken.Open(ctx, store.Root())
	if err != nil {
		return nil, err
	}
	resources = append(resources, apiTokens.Close)

	files := documentPaths(env, store.Root(), policy)
	catalog, err := documents.OpenCatalog(ctx, files.DocumentRoot)
	if err != nil {
		return nil, err
	}
	resources = append(resources, catalog.Close)
	service := documents.Service{Policy: policy, Catalog: catalog, DataRoot: files.DataRoot, PrivateRoot: files.PrivateRoot}

	limits := webapi.NewLoginLimiter(snapshot.Values.Int("WEB_LOGIN_ATTEMPTS_PER_5_MIN"), snapshot.Values.Int("WEB_LOGIN_ACCOUNT_ATTEMPTS_PER_5_MIN"))
	router.Session = webapi.SessionAPI{
		Sessions: sessions, Origins: origins, Limiter: limits, Login: client.Authenticate,
		Remember: func(ctx context.Context, identity directory.Identity) error {
			name := identity.Username
			if last := strings.LastIndexByte(name, '\\'); last >= 0 {
				name = name[last+1:]
			}
			_, err := policy.ExecContext(ctx, `INSERT INTO access_users(sid,sam,name) VALUES(?,?,?)
				ON CONFLICT(sid) DO UPDATE SET sam=excluded.sam`, identity.SID, name, name)
			return err
		},
	}
	router.Documents = webapi.DocumentAPI{Sessions: router.Session, Files: service, StateRoot: files.DocumentRoot}
	router.Agent = webapi.AgentAPI{Tokens: apiTokens, Accounts: client, Files: service, Indexed: router.Documents.ServeIdentity}
	router.AgentAdmin = webapi.AgentAdmin{Auth: router.Session, API: router.Agent}
	usage := webapi.UsageScanner{
		DB: policy, Data: files.DataRoot, Private: files.PrivateRoot,
		FSLogix:  setting(env, "FSLOGIX_ROOT", "/data/fslogix"),
		Interval: time.Duration(snapshot.Values.Int("WEB_USAGE_SCAN_INTERVAL_SECONDS")) * time.Second,
	}
	if err := usage.EnsureSchema(ctx); err != nil {
		return nil, err
	}

	workers, cancel := context.WithCancel(ctx)
	actions := &adminActions{ctx: workers, store: store, running: map[string]bool{}}
	usageDone := make(chan struct{})
	go func() {
		defer close(usageDone)
		usage.Run(workers)
	}()
	resources = append(resources, func() error {
		cancel()
		actions.stop()
		<-usageDone
		return nil
	})

	router.Admin = webapi.AdminAPI{
		Auth: router.Session, Config: store, Directory: client, Users: directoryReader(client),
		Access: access, Documents: catalog, Audit: audits, Trash: recycle,
		Usage: usage, Action: actions.start,
	}

	ready = true
	return cleanup, nil
}

func documentPaths(env map[string]string, root string, policy *sql.DB) documents.IndexOptions {
	return documents.IndexOptions{
		DocumentRoot: setting(env, "DOCUMENT_STATE_ROOT", filepath.Join(root, "documents")),
		DataRoot:     setting(env, "GROUP_ROOT", "/data/groups/data"),
		PrivateRoot:  setting(env, "PRIVATE_ROOT", "/data/private"),
		Policy:       policy,
	}
}

func runDocumentIndex(ctx context.Context, store *config.Store) error {
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		return err
	}
	env, err := store.Environment(snapshot, false)
	if err != nil {
		return err
	}
	policy, err := state.Open(ctx, env["STATE_DB_PATH"], true)
	if err != nil {
		return err
	}
	defer policy.Close()

	return documents.RunIndexer(ctx, documentPaths(env, store.Root(), policy))
}
