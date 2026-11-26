package accesscontrol

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unicode/utf8"

	"github.com/stuck-lehnert/domainshare/internal/directory"
	"golang.org/x/sys/unix"
)

const repairKey = "pendingRepair"

type repairIntent struct {
	Create string   `json:"create,omitempty"`
	Move   []string `json:"move,omitempty"`
}

func pathsEqualParent(path, parent string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && filepath.Dir(path) == parent && basename(filepath.Base(path))
}

func (m *Mutation) reverseMove(ctx context.Context, paths []string) error {
	if len(paths) != 2 {
		return errors.New("invalid pending folder move")
	}
	source, dest := paths[0], paths[1]
	sourceRoot, destRoot := filepath.Dir(source), filepath.Dir(dest)
	if sourceRoot == destRoot || !m.isManagedRoot(sourceRoot) || !m.isManagedRoot(destRoot) ||
		!pathsEqualParent(source, sourceRoot) || !pathsEqualParent(dest, destRoot) {
		return errors.New("unsafe pending folder move")
	}
	row, err := scanFolder(m.db.QueryRowContext(ctx, folderSelect+" WHERE path=?", source))
	if err != nil || m.root(row.Active) != sourceRoot || filepath.Base(dest) != row.Name {
		return errors.New("pending move does not match stored managed folder")
	}
	from, err := openDirPath(sourceRoot, false)
	if err != nil {
		return err
	}
	defer from.Close()
	hasSource, err := inspectEntry(from, filepath.Base(source))
	if err != nil {
		return err
	}
	to, err := openDirPath(destRoot, false)
	if errors.Is(err, os.ErrNotExist) && hasSource {
		return nil // interruption before the destination root was created
	}
	if err != nil {
		return err
	}
	defer to.Close()
	hasDest, err := inspectEntry(to, filepath.Base(dest))
	if err != nil {
		return err
	}
	switch {
	case hasSource && hasDest:
		return Conflict("Unterbrochene Ordneränderung: beide Pfade bleiben erhalten")
	case hasSource:
		return nil
	case hasDest:
		return moveFolder(to, filepath.Base(dest), from, filepath.Base(source))
	default:
		return errors.New("missing pending move source and destination; no empty folder created")
	}
}

func (m *Mutation) isManagedRoot(path string) bool {
	return path == m.cfg.GroupRoot || path == m.cfg.ArchiveRoot
}

// RecoverPending repairs an interrupted admin update and keeps the journal on
// failure. A created folder is adopted without individual grants to retain files.
func (m *Mutation) RecoverPending(ctx context.Context) error {
	data, pending, err := readSetting(ctx, m.db, repairKey)
	if err != nil || !pending {
		return err
	}
	var intent repairIntent
	if err := json.Unmarshal([]byte(data), &intent); err != nil {
		return err
	}
	if len(intent.Move) != 0 {
		if err := m.reverseMove(ctx, intent.Move); err != nil {
			return err
		}
	}

	err = writeTransaction(ctx, m.db, func(db database) error {
		if intent.Create != "" {
			if err := m.adoptInterruptedCreate(ctx, db, intent.Create); err != nil {
				return err
			}
		}
		if err := m.syncPermissions(ctx, db, true); err != nil {
			return err
		}
		if err := markDisconnect(ctx, db); err != nil {
			return err
		}
		return clearSetting(ctx, db, repairKey)
	})
	if err == nil {
		m.logf("Recovered interrupted admin access update")
	}
	return err
}

func (m *Mutation) adoptInterruptedCreate(ctx context.Context, db database, path string) error {
	name, valid := validFolderName(filepath.Base(path))
	if !valid || !pathsEqualParent(path, m.cfg.GroupRoot) || filepath.Base(path) != name {
		return errors.New("unsafe pending folder creation")
	}
	root, err := openDirPath(m.cfg.GroupRoot, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	found, err := inspectEntry(root, name)
	if err != nil || !found {
		return err
	}
	var known bool
	if err := db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM shares WHERE path=?)", path).Scan(&known); err != nil {
		return err
	}
	if known {
		return nil
	}
	return createFolderRecord(ctx, db, name, path)
}

type changePlan struct {
	action string
	name   string
	folder folderRow
	rules  []Permission
	intent repairIntent
}

// ApplyChange serializes policy, filesystem changes and ACL repair under the
// reconciliation lock. Pass nil current to fetch the current AD users.
func (s *Service) ApplyChange(ctx context.Context, body map[string]any, actor string, current map[string]Principal) (Snapshot, error) {
	action, _ := body["action"].(string)
	switch action {
	case "create-folder", "set-permissions", "archive-folder", "restore-folder":
	default:
		return Snapshot{}, Invalid("Unbekannte Verwaltungsaktion")
	}
	id, idOK := body["id"].(string)
	if body["id"] != nil && (!idOK || id == "" || utf8.RuneCountInString(id) > 120) {
		return Snapshot{}, Invalid("Ungültige ID")
	}
	details, err := json.Marshal(body)
	if err != nil {
		return Snapshot{}, Invalid("Ungültige Verwaltungsdaten")
	}
	var snapshot Snapshot
	err = s.WithMutation(ctx, func(m *Mutation) error {
		if err := m.Migrate(ctx); err != nil {
			return err
		}
		if current == nil {
			var err error
			current, _, err = m.directory(ctx, false)
			if err != nil {
				return err
			}
			if current == nil {
				current = map[string]Principal{}
			}
		}
		if err := m.CacheUsers(ctx, current); err != nil {
			return err
		}
		if err := m.RecoverPending(ctx); err != nil {
			return err
		}
		plan, err := m.planChange(ctx, action, id, body, current)
		if err != nil {
			return err
		}
		if err := m.commitChange(ctx, plan, actor, string(details)); err != nil {
			return err
		}
		if err := m.CloseDataConnections(ctx, true); err != nil {
			return err
		}
		snapshot, err = m.Snapshot(ctx, current)
		return err
	})
	return snapshot, err
}

func (m *Mutation) planChange(ctx context.Context, action, id string, body map[string]any, users map[string]Principal) (changePlan, error) {
	plan := changePlan{action: action}
	if action == "create-folder" {
		raw, _ := body["name"].(string)
		name, valid := validFolderName(raw)
		if !valid {
			return plan, Invalid("Ungültiger Name")
		}
		var exists bool
		if err := m.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM shares WHERE shareName=? COLLATE NOCASE)`, name).Scan(&exists); err != nil {
			return plan, err
		}
		if exists {
			return plan, Invalid("Ordnername ist bereits vergeben")
		}
		root, err := openDirPath(m.cfg.GroupRoot, true)
		if err != nil {
			return plan, err
		}
		defer root.Close()
		present, err := inspectEntry(root, name)
		if err != nil {
			return plan, err
		}
		if present {
			return plan, Conflict("Zielordner existiert bereits")
		}
		plan.name, plan.intent.Create = name, filepath.Join(m.cfg.GroupRoot, name)
		return plan, nil
	}

	folder, err := findFolder(ctx, m.db, id)
	if errors.Is(err, sql.ErrNoRows) {
		return plan, Invalid("Ordner nicht gefunden")
	}
	if err != nil {
		return plan, err
	}
	plan.folder = folder
	if action == "set-permissions" {
		plan.rules, err = m.validateRules(ctx, id, body["permissions"], users)
		return plan, err
	}
	if folder.Active == (action == "restore-folder") {
		return plan, Invalid("Ordner hat diesen Status bereits")
	}
	if _, err := m.folderComponent(folder); err != nil {
		return plan, err
	}
	name, valid := validFolderName(folder.Name)
	if !valid || name != folder.Name {
		return plan, Invalid("Ungültiger Name")
	}
	plan.name = name
	plan.intent.Move = []string{folder.Path, filepath.Join(m.root(!folder.Active), name)}
	return plan, nil
}

func parseLevel(value any) (int, bool) {
	switch n := value.(type) {
	case int:
		return n, n >= 0 && n <= 3
	case json.Number:
		level, err := n.Int64()
		return int(level), err == nil && level >= 0 && level <= 3
	default:
		return 0, false
	}
}

func (m *Mutation) validateRules(ctx context.Context, folderID string, value any, current map[string]Principal) ([]Permission, error) {
	input, ok := value.([]any)
	if !ok {
		return nil, Invalid("Berechtigungen müssen eine Liste sein")
	}
	previous, err := readRules(ctx, m.db, &folderID)
	if err != nil {
		return nil, err
	}
	old := map[string]ruleRow{}
	for _, rule := range previous {
		old[rule.PrincipalID] = rule
	}
	seen := map[string]bool{}
	result := make([]Permission, 0, len(input))
	for _, item := range input {
		fields, _ := item.(map[string]any)
		kind, _ := fields["kind"].(string)
		sid, _ := fields["principalId"].(string)
		level, valid := parseLevel(fields["level"])
		if kind != "user" || sid == "" || !valid {
			return nil, Invalid("Ungültige Berechtigung")
		}
		if seen[sid] {
			return nil, Invalid("Doppelte Berechtigung")
		}
		seen[sid] = true
		user, live := current[sid]
		oldRule, known := old[sid]
		if !live && !known {
			return nil, Invalid("Unbekannter AD-Benutzer")
		}
		if level != 0 && (directory.IsExcludedUser(user.SAM) || directory.IsExcludedUser(oldRule.SAM)) {
			return nil, Invalid("Systemkonto kann keine Ordnerberechtigung erhalten")
		}
		result = append(result, Permission{Kind: kind, PrincipalID: sid, Level: level})
	}
	return result, nil
}

func (m *Mutation) commitChange(ctx context.Context, plan changePlan, actor, details string) error {
	intent, err := json.Marshal(plan.intent)
	if err != nil {
		return err
	}
	if err := addSetting(ctx, m.db, repairKey, string(intent)); err != nil {
		return err
	}

	var changedPath, aclStarted bool
	err = writeTransaction(ctx, m.db, func(db database) error {
		if err := m.applyPlan(ctx, db, plan, &changedPath); err != nil {
			return err
		}
		aclStarted = true
		if err := m.syncPermissions(ctx, db, false); err != nil {
			return err
		}
		if err := markDisconnect(ctx, db); err != nil {
			return err
		}
		if err := recordChange(ctx, db, actor, plan.action, details); err != nil {
			return err
		}
		return clearSetting(ctx, db, repairKey)
	})
	if err == nil {
		return nil
	}

	// Context cancellation must not delete repair intent or reverse a commit
	// whose result was ambiguous. Check the persisted marker before cleanup.
	cleanup := context.WithoutCancel(ctx)
	if recoveryErr := m.rollbackChange(cleanup, plan, changedPath, aclStarted); recoveryErr != nil {
		m.logf("ERROR: Access rollback repair failed: %v", recoveryErr)
		return errors.Join(err, recoveryErr)
	}
	return err
}

func (m *Mutation) applyPlan(ctx context.Context, db database, plan changePlan, changedPath *bool) error {
	switch plan.action {
	case "create-folder":
		root, err := openDirPath(m.cfg.GroupRoot, false)
		if err != nil {
			return err
		}
		defer root.Close()
		if err := unix.Mkdirat(int(root.Fd()), plan.name, 0o700); err != nil {
			if errors.Is(err, unix.EEXIST) {
				return Conflict("Zielordner existiert bereits")
			}
			return err
		}
		*changedPath = true
		return createFolderRecord(ctx, db, plan.name, plan.intent.Create)
	case "set-permissions":
		if _, err := db.ExecContext(ctx, "DELETE FROM folder_permissions WHERE folderId=?", plan.folder.ID); err != nil {
			return err
		}
		for _, rule := range plan.rules {
			if _, err := db.ExecContext(ctx, "INSERT INTO folder_permissions VALUES(?,?,?,?)", plan.folder.ID, rule.Kind, rule.PrincipalID, rule.Level); err != nil {
				return err
			}
		}
		return nil
	default:
		from, err := openDirPath(m.root(plan.folder.Active), false)
		if err != nil {
			return err
		}
		defer from.Close()
		to, err := openDirPath(m.root(!plan.folder.Active), true)
		if err != nil {
			return err
		}
		defer to.Close()
		if err := moveFolder(from, filepath.Base(plan.folder.Path), to, plan.name); err != nil {
			if errors.Is(err, unix.EEXIST) {
				return Conflict("Zielordner existiert bereits")
			}
			return err
		}
		*changedPath = true
		_, err = db.ExecContext(ctx, "UPDATE shares SET path=?,isActive=?,aclSignature='' WHERE objectGUID=?",
			plan.intent.Move[1], !plan.folder.Active, plan.folder.ID)
		return err
	}
}

func (m *Mutation) rollbackChange(ctx context.Context, plan changePlan, changedPath, aclStarted bool) error {
	_, pending, err := readSetting(ctx, m.db, repairKey)
	if err != nil || !pending {
		return err
	}
	if changedPath && len(plan.intent.Move) != 0 {
		if err := m.reverseMove(ctx, plan.intent.Move); err != nil {
			return err
		}
	}
	if changedPath && plan.intent.Create != "" {
		root, err := openDirPath(m.cfg.GroupRoot, false)
		if err != nil {
			return err
		}
		err = unix.Unlinkat(int(root.Fd()), plan.name, unix.AT_REMOVEDIR)
		root.Close()
		if err != nil && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("retain interrupted folder for recovery: %w", err)
		}
	}
	if aclStarted {
		return m.RecoverPending(ctx)
	}
	return clearSetting(ctx, m.db, repairKey)
}
