package documents

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"

	"github.com/stuck-lehnert/domainshare/internal/directory"
)

type Service struct {
	Catalog     *sql.DB
	Policy      *sql.DB
	DataRoot    string
	PrivateRoot string
}

type Source struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Label string `json:"label"`
	root  string
	owner *int
}

func directChild(root, path string) (string, bool) {
	root, rootErr := filepath.Abs(root)
	path, pathErr := filepath.Abs(path)
	return path, rootErr == nil && pathErr == nil && filepath.Dir(path) == root
}

type catalogReader interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func (service Service) allowedSources(ctx context.Context, identity directory.Identity, live bool) (map[string]Source, error) {
	return service.allowedSourcesInCatalog(ctx, identity, live, service.Catalog)
}

// Use the same catalog snapshot for source authorization and indexed results.
// Share permissions still come independently from the current policy database.
func (service Service) allowedSourcesInCatalog(ctx context.Context, identity directory.Identity, live bool, catalog catalogReader) (map[string]Source, error) {
	allowed := make(map[string]Source)
	if identity.SID == "" || directory.IsExcludedUser(identity.Username) {
		return allowed, nil
	}

	policy, err := service.Policy.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer policy.Rollback()

	var account string
	err = policy.QueryRowContext(ctx, "SELECT sam FROM access_users WHERE sid=?", identity.SID).Scan(&account)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if directory.IsExcludedUser(account) {
		return allowed, nil
	}

	rows, err := policy.QueryContext(ctx, `SELECT s.objectGUID,s.shareName,s.path
		FROM shares s WHERE s.isActive=1 AND (? OR EXISTS (
			SELECT 1 FROM folder_permissions p WHERE p.folderId=s.objectGUID AND p.kind='user' AND p.principalId=? AND p.level>=1
		))`, identity.Admin(), identity.SID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	data := make(map[string]Source)
	for rows.Next() {
		var id, name, path string
		if err := rows.Scan(&id, &name, &path); err != nil {
			return nil, err
		}
		if root, ok := directChild(service.DataRoot, path); ok {
			source := Source{ID: "data:" + id, Label: name, Kind: "data", root: root}
			data[source.ID] = source
			if live {
				allowed[source.ID] = source
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	if err := policy.Commit(); err != nil {
		return nil, err
	}

	query := "SELECT id,kind,label,root,owner_sid FROM document_sources"
	var args []any
	if live {
		query += " WHERE kind='private' AND owner_sid=?"
		args = append(args, identity.SID)
	} else {
		query += " WHERE kind='data' OR (kind='private' AND owner_sid=?)"
		args = append(args, identity.SID)
	}
	indexed, err := catalog.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer indexed.Close()
	for indexed.Next() {
		var source Source
		var sid string
		if err := indexed.Scan(&source.ID, &source.Kind, &source.Label, &source.root, &sid); err != nil {
			return nil, err
		}
		switch source.Kind {
		case "data":
			// Old index paths must match the current policy path exactly.
			if folder, ok := data[source.ID]; ok && source.root == folder.root {
				allowed[source.ID] = source
			}
		case "private":
			path, safe := directChild(service.PrivateRoot, source.root)
			if sid == identity.SID && identity.UID != nil && safe && strings.HasPrefix(source.ID, "private:") {
				source.root, source.owner = path, identity.UID
				allowed[source.ID] = source
			}
		}
	}
	return allowed, indexed.Err()
}
