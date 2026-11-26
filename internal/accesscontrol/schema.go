package accesscontrol

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type database interface {
	queryer
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

const permissionsColumns = `(
	folderId TEXT NOT NULL REFERENCES shares(objectGUID) ON DELETE CASCADE,
	kind TEXT NOT NULL CHECK(kind = 'user'), principalId TEXT NOT NULL,
	level INTEGER NOT NULL CHECK(level BETWEEN 0 AND 3), PRIMARY KEY(folderId, kind, principalId)
)`

const schema = `
CREATE TABLE IF NOT EXISTS shares (
	objectGUID TEXT PRIMARY KEY, samAccountName TEXT NOT NULL, shareName TEXT NOT NULL,
	path TEXT NOT NULL, createdAt TIMESTAMP NOT NULL, lastSeenAt TIMESTAMP NOT NULL,
	isActive INTEGER NOT NULL, aclSignature TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS access_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS access_users (sid TEXT PRIMARY KEY, sam TEXT NOT NULL, name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS folder_permissions ` + permissionsColumns + `;
CREATE TABLE IF NOT EXISTS access_changes (
	id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, details TEXT NOT NULL
);`

func writeTransaction(ctx context.Context, db *sql.DB, work func(database) error) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}

	committed := false
	defer func() {
		if committed {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := conn.ExecContext(cleanup, "ROLLBACK"); err != nil {
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		}
	}()
	if err := work(conn); err != nil {
		return err
	}
	_, err = conn.ExecContext(ctx, "COMMIT")
	committed = err == nil
	return err
}

func ensureSchema(ctx context.Context, db database) error {
	if _, err := db.ExecContext(ctx, schema); err != nil {
		return err
	}
	var signatureColumn bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pragma_table_info('shares') WHERE name='aclSignature')`).Scan(&signatureColumn); err != nil {
		return err
	}
	if !signatureColumn {
		if _, err := db.ExecContext(ctx, "ALTER TABLE shares ADD COLUMN aclSignature TEXT NOT NULL DEFAULT ''"); err != nil {
			return err
		}
	}

	var ddl string
	if err := db.QueryRowContext(ctx, "SELECT sql FROM sqlite_master WHERE name='folder_permissions'").Scan(&ddl); err != nil {
		return err
	}
	if !strings.Contains(ddl, "'group'") {
		return nil
	}

	var unresolved bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM folder_permissions p
		LEFT JOIN access_groups g ON p.principalId=g.id WHERE p.kind='group' AND g.id IS NULL)`).Scan(&unresolved); err != nil {
		return err
	}
	if unresolved {
		return errors.New("cannot migrate unresolved stored group permission")
	}

	// Direct permissions, including explicit level 0, override group grants.
	if _, err := db.ExecContext(ctx, `CREATE TABLE individual_permissions `+permissionsColumns+`;
		INSERT INTO individual_permissions SELECT * FROM folder_permissions WHERE kind='user';
		INSERT OR IGNORE INTO individual_permissions
		SELECT p.folderId,'user',m.userSid,MAX(p.level) FROM folder_permissions p
		JOIN access_members m ON p.kind='group' AND p.principalId=m.groupId GROUP BY p.folderId,m.userSid;
		DROP TABLE folder_permissions;
		ALTER TABLE individual_permissions RENAME TO folder_permissions;
		DROP TABLE access_members;
		DROP TABLE access_groups;`); err != nil {
		return err
	}
	return recordChange(ctx, db, "system", "migrate-individual-permissions", "{}")
}

func timestamp() string { return time.Now().UTC().Format("2006-01-02T15:04:05-07:00") }

func recordChange(ctx context.Context, db database, actor, action, details string) error {
	_, err := db.ExecContext(ctx, "INSERT INTO access_changes(timestamp,actor,action,details) VALUES(?,?,?,?)",
		timestamp(), actor, action, details)
	return err
}

func readSetting(ctx context.Context, db queryer, key string) (string, bool, error) {
	var value string
	err := db.QueryRowContext(ctx, "SELECT value FROM access_settings WHERE key=?", key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return value, err == nil, err
}

func addSetting(ctx context.Context, db database, key, value string) error {
	_, err := db.ExecContext(ctx, "INSERT INTO access_settings(key,value) VALUES(?,?)", key, value)
	return err
}

func clearSetting(ctx context.Context, db database, key string) error {
	_, err := db.ExecContext(ctx, "DELETE FROM access_settings WHERE key=?", key)
	return err
}

type folderRow struct {
	ID, SAM, Name, Path, Signature string
	Active                         bool
}

const folderSelect = "SELECT objectGUID,samAccountName,shareName,path,aclSignature,isActive FROM shares"

func scanFolder(scanner interface{ Scan(...any) error }) (folderRow, error) {
	var folder folderRow
	err := scanner.Scan(&folder.ID, &folder.SAM, &folder.Name, &folder.Path, &folder.Signature, &folder.Active)
	return folder, err
}

func findFolder(ctx context.Context, db queryer, id string) (folderRow, error) {
	return scanFolder(db.QueryRowContext(ctx, folderSelect+" WHERE objectGUID=?", id))
}

func readFolders(ctx context.Context, db queryer, activeOnly bool) ([]folderRow, error) {
	query := folderSelect
	if activeOnly {
		query += " WHERE isActive=1"
	}
	rows, err := db.QueryContext(ctx, query+" ORDER BY objectGUID")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	folders := []folderRow{}
	for rows.Next() {
		folder, err := scanFolder(rows)
		if err != nil {
			return nil, err
		}
		folders = append(folders, folder)
	}
	return folders, rows.Err()
}

func createFolderRecord(ctx context.Context, db database, name, path string) error {
	id, err := uuid.NewRandom()
	if err != nil {
		return err
	}
	stamp := timestamp()
	_, err = db.ExecContext(ctx, `INSERT INTO shares(objectGUID,samAccountName,shareName,path,createdAt,lastSeenAt,isActive,aclSignature)
		VALUES(?,?,?,?,?,?,1,'')`, id.String(), name, name, path, stamp, stamp)
	return err
}
