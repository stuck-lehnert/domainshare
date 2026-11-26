package accesscontrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/stuck-lehnert/domainshare/internal/directory"
	"golang.org/x/text/cases"
)

var caseFolder = cases.Fold()

func (m *Mutation) directory(ctx context.Context, includeGroups bool) (map[string]Principal, map[string]Principal, error) {
	if m.cfg.ReadDirectory == nil {
		return nil, nil, errors.New("managed access directory reader is not configured")
	}
	return m.cfg.ReadDirectory(ctx, includeGroups)
}

// Migrate adopts the previous permissions only once. Layout repair is separate
// from AD import and can be resumed after the initial commit.
func (m *Mutation) Migrate(ctx context.Context) error {
	_, initialized, err := readSetting(ctx, m.db, "managed")
	if err != nil {
		return err
	}
	if !initialized {
		if err := m.importLegacy(ctx); err != nil {
			return err
		}
	}
	return m.migrateFolderLayout(ctx)
}

func sidDomain(sid string) (string, int, bool) {
	i := strings.LastIndexByte(sid, '-')
	if i < 0 {
		return "", 0, false
	}
	rid, err := strconv.ParseUint(sid[i+1:], 10, 32)
	return sid[:i], int(rid), err == nil
}

func resolveMembership(group Principal, users, groups map[string]Principal, byDN map[string]string) ([]string, error) {
	visited := map[string]bool{}
	selected := map[string]bool{}
	var visit func(Principal) error
	visit = func(group Principal) error {
		if visited[group.DN] {
			return nil
		}
		visited[group.DN] = true
		groupDomain, rid, valid := sidDomain(group.SID)
		if !valid {
			return fmt.Errorf("invalid legacy group SID %q", group.SID)
		}
		for sid, user := range users {
			userDomain, _, ok := sidDomain(sid)
			if ok && userDomain == groupDomain && user.PrimaryRID == rid && !directory.IsExcludedUser(user.SAM) {
				selected[sid] = true
			}
		}
		for _, dn := range group.Members {
			if nested, ok := groups[dn]; ok {
				if err := visit(nested); err != nil {
					return err
				}
			} else if sid, ok := byDN[dn]; ok {
				if !directory.IsExcludedUser(users[sid].SAM) {
					selected[sid] = true
				}
			} else {
				return fmt.Errorf("cannot import unresolved member %s; migration will retry", dn)
			}
		}
		return nil
	}
	if err := visit(group); err != nil {
		return nil, err
	}
	result := make([]string, 0, len(selected))
	for sid := range selected {
		result = append(result, sid)
	}
	slices.Sort(result)
	return result, nil
}

func (m *Mutation) importLegacy(ctx context.Context) error {
	folders, err := readFolders(ctx, m.db, true)
	if err != nil {
		return err
	}
	var users, groups map[string]Principal
	if len(folders) != 0 {
		users, groups, err = m.directory(ctx, true)
		if err != nil {
			return err
		}
	}
	bySAM := map[string]Principal{}
	for dn, group := range groups {
		if group.DN == "" {
			group.DN = dn
			groups[dn] = group
		}
		bySAM[caseFolder.String(group.SAM)] = group
	}
	byDN := map[string]string{}
	for sid, user := range users {
		byDN[user.DN] = sid
	}
	imports := make(map[string][]string, len(folders))
	for _, folder := range folders {
		group, ok := bySAM[caseFolder.String(folder.SAM)]
		if !ok {
			return fmt.Errorf("cannot import group %s; migration will retry", folder.SAM)
		}
		members, err := resolveMembership(group, users, groups, byDN)
		if err != nil {
			return err
		}
		imports[folder.ID] = members
	}

	return writeTransaction(ctx, m.db, func(db database) error {
		if err := cacheUsers(ctx, db, users); err != nil {
			return err
		}
		for _, folder := range folders {
			for _, sid := range imports[folder.ID] {
				if _, err := db.ExecContext(ctx, "INSERT INTO folder_permissions VALUES(?,'user',?,3)", folder.ID, sid); err != nil {
					return err
				}
			}
		}
		if err := m.adoptUntracked(ctx, db); err != nil {
			return err
		}
		if err := addSetting(ctx, db, "managed", "1"); err != nil {
			return err
		}
		_, err := db.ExecContext(ctx, "UPDATE shares SET aclSignature=''")
		return err
	})
}

func (m *Mutation) adoptUntracked(ctx context.Context, db database) error {
	root, err := openDirPath(m.cfg.GroupRoot, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	folders, err := readFolders(ctx, db, false)
	if err != nil {
		return err
	}
	known := map[string]bool{}
	for _, folder := range folders {
		known[filepath.Clean(folder.Path)] = true
	}
	entries, err := root.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(root.Name(), entry.Name())
		if entry.IsDir() && !strings.EqualFold(entry.Name(), ".trash") && !known[path] {
			if err := createFolderRecord(ctx, db, entry.Name(), path); err != nil {
				return err
			}
		}
	}
	return nil
}

type layoutMove struct {
	FolderID    string `json:"folderId"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Name        string `json:"name"`
}

func (m *Mutation) legacyComponent(row folderRow, path string) (string, error) {
	name := filepath.Base(path)
	guid, guidErr := uuid.Parse(row.ID)
	nameGUID, nameErr := uuid.Parse(name)
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) != filepath.Dir(m.cfg.GroupRoot) ||
		guidErr != nil || nameErr != nil || guid != nameGUID {
		return "", fmt.Errorf("unsafe legacy folder path: %q", path)
	}
	return name, nil
}

func (m *Mutation) finishLayout(ctx context.Context, move layoutMove) error {
	row, err := findFolder(ctx, m.db, move.FolderID)
	if err != nil || row.Path != move.Source {
		return errors.New("folder layout recovery does not match stored folder; all paths retained")
	}
	source, err := m.legacyComponent(row, move.Source)
	if err != nil {
		return err
	}
	name, valid := validFolderName(move.Name)
	root := m.root(row.Active)
	if !valid || name != move.Name || filepath.Join(root, name) != move.Destination {
		return errors.New("unsafe folder layout recovery destination")
	}
	from, err := openDirPath(filepath.Dir(m.cfg.GroupRoot), false)
	if err != nil {
		return err
	}
	defer from.Close()
	to, err := openDirPath(root, false)
	if err != nil {
		return err
	}
	defer to.Close()
	hasSource, err := inspectEntry(from, source)
	if err != nil {
		return err
	}
	hasDest, err := inspectEntry(to, name)
	if err != nil {
		return err
	}
	switch {
	case hasSource && hasDest:
		return fmt.Errorf("folder layout conflict; both paths retained: %s -> %s", move.Source, move.Destination)
	case hasSource:
		if err := moveFolder(from, source, to, name); err != nil {
			return err
		}
	case !hasDest:
		return errors.New("folder layout cannot find source or destination; no empty folder created")
	}

	details, err := json.Marshal(move)
	if err != nil {
		return err
	}
	err = writeTransaction(ctx, m.db, func(db database) error {
		if _, err := db.ExecContext(ctx, "UPDATE shares SET path=?,shareName=?,aclSignature='' WHERE objectGUID=?", move.Destination, move.Name, move.FolderID); err != nil {
			return err
		}
		if err := recordChange(ctx, db, "system", "migrate-folder-layout", string(details)); err != nil {
			return err
		}
		return clearSetting(ctx, db, "pendingFolderLayout")
	})
	if err == nil {
		m.logf("Migrated legacy folder without overwriting data: %s -> %s", move.Source, move.Destination)
	}
	return err
}

func (m *Mutation) migrateFolderLayout(ctx context.Context) error {
	data, pending, err := readSetting(ctx, m.db, "pendingFolderLayout")
	if err != nil {
		return err
	}
	if pending {
		var move layoutMove
		if err := json.Unmarshal([]byte(data), &move); err != nil {
			return err
		}
		if err := m.finishLayout(ctx, move); err != nil {
			return err
		}
	}
	folders, err := readFolders(ctx, m.db, false)
	if err != nil {
		return err
	}
	var legacy []int
	for i, folder := range folders {
		if filepath.Dir(folder.Path) == m.root(folder.Active) {
			if _, err := m.folderComponent(folder); err != nil {
				return err
			}
			continue
		}
		if _, err := m.legacyComponent(folder, folder.Path); err != nil {
			return err
		}
		file, err := openDirPath(folder.Path, false)
		if err != nil {
			return fmt.Errorf("legacy folder unavailable; no empty folder created: %w", err)
		}
		file.Close()
		legacy = append(legacy, i)
	}
	for _, index := range legacy {
		folder := folders[index]
		root, err := openDirPath(m.root(folder.Active), true)
		if err != nil {
			return err
		}
		entries, err := root.ReadDir(-1)
		root.Close()
		if err != nil {
			return err
		}
		used := map[string]bool{}
		for _, entry := range entries {
			used[caseFolder.String(entry.Name())] = true
		}
		for _, other := range folders {
			if other.ID != folder.ID {
				used[caseFolder.String(other.Name)] = true
			}
		}
		name := layoutName(folder, used)
		move := layoutMove{folder.ID, folder.Path, filepath.Join(m.root(folder.Active), name), name}
		details, err := json.Marshal(move)
		if err != nil {
			return err
		}
		if err := addSetting(ctx, m.db, "pendingFolderLayout", string(details)); err != nil {
			return err
		}
		if err := m.finishLayout(ctx, move); err != nil {
			return err
		}
		folders[index].Name = name
	}
	return nil
}

func layoutName(folder folderRow, used map[string]bool) string {
	clean := strings.Map(func(r rune) rune {
		if r < 32 || r == 127 || strings.ContainsRune(`\/:*?"<>|`, r) {
			return '_'
		}
		return r
	}, strings.TrimSpace(folder.Name))
	base := strings.Join(strings.Fields(strings.TrimRight(strings.TrimSpace(clean), ".")), " ")
	if runes := []rune(base); len(runes) > 120 {
		base = string(runes[:120])
	}
	if _, ok := validFolderName(base); !ok {
		base = folder.ID
	}
	candidate := base
	for i := 1; used[caseFolder.String(candidate)]; i++ {
		suffix := "_" + folder.ID[:min(8, len(folder.ID))]
		if i > 1 {
			suffix += "_" + strconv.Itoa(i)
		}
		runes := []rune(base)
		prefix := strings.TrimRight(string(runes[:min(len(runes), 120-len(suffix))]), " ._")
		if prefix == "" {
			prefix = "group"
		}
		candidate = prefix + suffix
	}
	return candidate
}
