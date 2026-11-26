package accesscontrol

import (
	"context"
	"database/sql"
	"sort"
	"strings"

	"github.com/stuck-lehnert/domainshare/internal/directory"
)

type Permission struct {
	Kind        string `json:"kind"`
	PrincipalID string `json:"principalId"`
	Level       int    `json:"level"`
}

type User struct {
	SID       string `json:"sid"`
	SAM       string `json:"sam"`
	Name      string `json:"name"`
	Available *bool  `json:"available,omitempty"`
}

type Folder struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Active      bool         `json:"active"`
	Permissions []Permission `json:"permissions"`
}

type Snapshot struct {
	Users       []User   `json:"users"`
	Folders     []Folder `json:"folders"`
	FetchedAt   string   `json:"fetchedAt"`
	Initialized bool     `json:"initialized"`
}

type Member struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	SAM     string   `json:"sam"`
	Type    string   `json:"type"`
	Level   int      `json:"level"`
	Members []Member `json:"members"`
}

type ReportGroup struct {
	GUID       string   `json:"guid"`
	Name       string   `json:"name"`
	SAM        string   `json:"sam"`
	Folder     string   `json:"folder"`
	Active     bool     `json:"active"`
	UserCount  int      `json:"userCount"`
	GroupCount int      `json:"groupCount"`
	Members    []Member `json:"members"`
}

type Report struct {
	Groups    []ReportGroup `json:"groups"`
	FetchedAt string        `json:"fetchedAt"`
	Truncated bool          `json:"truncated"`
}

func cacheUsers(ctx context.Context, db database, users map[string]Principal) error {
	for sid, user := range users {
		if _, err := db.ExecContext(ctx, `INSERT INTO access_users(sid,sam,name) VALUES(?,?,?)
			ON CONFLICT(sid) DO UPDATE SET sam=excluded.sam,name=excluded.name`, sid, user.SAM, user.Name); err != nil {
			return err
		}
	}
	return nil
}

func (m *Mutation) CacheUsers(ctx context.Context, users map[string]Principal) error {
	return writeTransaction(ctx, m.db, func(db database) error { return cacheUsers(ctx, db, users) })
}

type ruleRow struct {
	FolderID string `json:"folderId"`
	Permission
	SAM string `json:"-"`
}

func readRules(ctx context.Context, db queryer, folderID *string) ([]ruleRow, error) {
	query := `SELECT p.folderId,p.kind,p.principalId,p.level,coalesce(u.sam,'')
		FROM folder_permissions p LEFT JOIN access_users u ON p.principalId = u.sid`
	var args []any
	if folderID != nil {
		query += " WHERE p.folderId=?"
		args = append(args, *folderID)
	}
	rows, err := db.QueryContext(ctx, query+" ORDER BY p.kind,p.principalId", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rules := []ruleRow{}
	for rows.Next() {
		var row ruleRow
		if err := rows.Scan(&row.FolderID, &row.Kind, &row.PrincipalID, &row.Level, &row.SAM); err != nil {
			return nil, err
		}
		rules = append(rules, row)
	}
	return rules, rows.Err()
}

func effectiveLevels(ctx context.Context, db queryer, folderID string) (map[string]int, error) {
	rules, err := readRules(ctx, db, &folderID)
	if err != nil {
		return nil, err
	}
	levels := map[string]int{}
	for _, rule := range rules {
		if !directory.IsExcludedUser(rule.SAM) {
			levels[rule.PrincipalID] = rule.Level
		}
	}
	return levels, nil
}

func (s *Service) EffectiveLevels(ctx context.Context, folderID string) (map[string]int, error) {
	return effectiveLevels(ctx, s.db, folderID)
}

// Snapshot reads one consistent database view. EnsureSchema must have run once.
// A nil current map omits the available flag as in the legacy API.
func (s *Service) Snapshot(ctx context.Context, current map[string]Principal) (Snapshot, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Snapshot{}, err
	}
	defer tx.Rollback()
	result, err := readSnapshot(ctx, tx, current)
	if err != nil {
		return Snapshot{}, err
	}
	return result, tx.Commit()
}

func readSnapshot(ctx context.Context, db queryer, current map[string]Principal) (Snapshot, error) {
	result := Snapshot{Users: []User{}, Folders: []Folder{}, FetchedAt: timestamp()}
	_, initialized, err := readSetting(ctx, db, "managed")
	if err != nil {
		return Snapshot{}, err
	}
	result.Initialized = initialized

	rows, err := db.QueryContext(ctx, `SELECT sid,sam,name FROM access_users ORDER BY sam COLLATE NOCASE`)
	if err != nil {
		return Snapshot{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.SID, &user.SAM, &user.Name); err != nil {
			return Snapshot{}, err
		}
		if directory.IsExcludedUser(user.SAM) {
			continue
		}
		if current != nil {
			_, available := current[user.SID]
			user.Available = &available
		}
		result.Users = append(result.Users, user)
	}
	if err := rows.Err(); err != nil {
		return Snapshot{}, err
	}
	if err := rows.Close(); err != nil {
		return Snapshot{}, err
	}

	folders, err := readFolders(ctx, db, false)
	if err != nil {
		return Snapshot{}, err
	}
	rules, err := readRules(ctx, db, nil)
	if err != nil {
		return Snapshot{}, err
	}
	byFolder := map[string][]Permission{}
	for _, rule := range rules {
		if !directory.IsExcludedUser(rule.SAM) {
			byFolder[rule.FolderID] = append(byFolder[rule.FolderID], rule.Permission)
		}
	}
	// SQLite NOCASE folds ASCII only.
	caseASCII := func(value string) string {
		return strings.Map(func(r rune) rune {
			if r >= 'A' && r <= 'Z' {
				return r + ('a' - 'A')
			}
			return r
		}, value)
	}
	sort.SliceStable(folders, func(i, j int) bool { return caseASCII(folders[i].Name) < caseASCII(folders[j].Name) })
	for _, row := range folders {
		permissions, ok := byFolder[row.ID]
		if !ok {
			permissions = []Permission{}
		}
		result.Folders = append(result.Folders, Folder{ID: row.ID, Name: row.Name, Active: row.Active, Permissions: permissions})
	}
	return result, nil
}

func (s *Service) Report(ctx context.Context) (Report, error) {
	snapshot, err := s.Snapshot(ctx, nil)
	if err != nil {
		return Report{}, err
	}
	users := map[string]User{}
	for _, user := range snapshot.Users {
		users[user.SID] = user
	}
	report := Report{Groups: []ReportGroup{}, FetchedAt: snapshot.FetchedAt}
	for _, folder := range snapshot.Folders {
		if !folder.Active {
			continue
		}
		group := ReportGroup{GUID: folder.ID, Name: folder.Name, SAM: folder.Name, Folder: folder.Name,
			Active: true, Members: []Member{}}
		for _, rule := range folder.Permissions {
			if rule.Kind != "user" || rule.Level == 0 {
				continue
			}
			sid := rule.PrincipalID
			user, known := users[sid]
			if !known {
				user = User{Name: sid, SAM: sid}
			}
			group.Members = append(group.Members, Member{ID: sid, Name: user.Name, SAM: user.SAM,
				Type: "user", Level: rule.Level, Members: []Member{}})
		}
		group.UserCount = len(group.Members)
		report.Groups = append(report.Groups, group)
	}
	return report, nil
}
