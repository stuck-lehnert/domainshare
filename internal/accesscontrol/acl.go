package accesscontrol

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/stuck-lehnert/domainshare/internal/directory"
	"github.com/stuck-lehnert/domainshare/internal/sambaacl"
	"github.com/stuck-lehnert/domainshare/internal/trash"
)

func (s *Service) root(active bool) string {
	if active {
		return s.cfg.GroupRoot
	}
	return s.cfg.ArchiveRoot
}

func (s *Service) folderComponent(row folderRow) (string, error) {
	name := filepath.Base(row.Path)
	if !filepath.IsAbs(row.Path) || filepath.Clean(row.Path) != row.Path || filepath.Dir(row.Path) != s.root(row.Active) || !basename(name) || strings.EqualFold(name, ".trash") {
		return "", fmt.Errorf("unsafe managed folder path: %q", row.Path)
	}
	return name, nil
}

func revokeExcluded(ctx context.Context, db database) error {
	rules, err := readRules(ctx, db, nil)
	if err != nil {
		return err
	}
	removed := []ruleRow{}
	hadAccess := false
	for _, rule := range rules {
		if !directory.IsExcludedUser(rule.SAM) {
			continue
		}
		if _, err := db.ExecContext(ctx, "DELETE FROM folder_permissions WHERE folderId=? AND principalId=?", rule.FolderID, rule.PrincipalID); err != nil {
			return err
		}
		if _, err := db.ExecContext(ctx, "UPDATE shares SET aclSignature='' WHERE objectGUID=?", rule.FolderID); err != nil {
			return err
		}
		hadAccess = hadAccess || rule.Level != 0
		removed = append(removed, rule)
	}
	if len(removed) == 0 {
		return nil
	}
	if hadAccess {
		if err := markDisconnect(ctx, db); err != nil {
			return err
		}
	}
	details, err := json.Marshal(removed)
	if err != nil {
		return err
	}
	return recordChange(ctx, db, "system", "revoke-excluded-users", string(details))
}

const disconnectKey = "pendingExcludedRevocation"

func markDisconnect(ctx context.Context, db database) error {
	_, err := db.ExecContext(ctx, "INSERT OR REPLACE INTO access_settings VALUES(?, '1')", disconnectKey)
	return err
}

// CloseDataConnections disconnects Data clients only if requested or queued.
// A failure does not roll back the already committed access policy.
func (m *Mutation) CloseDataConnections(ctx context.Context, force bool) error {
	_, pending, err := readSetting(ctx, m.db, disconnectKey)
	if err != nil || (!force && !pending) {
		return err
	}
	if force && !pending {
		if err := markDisconnect(ctx, m.db); err != nil {
			return err
		}
	}
	if m.cfg.CloseDataConnections == nil {
		return errors.New("Data disconnect runner is not configured")
	}
	if err := m.cfg.CloseDataConnections(ctx); err != nil {
		return fmt.Errorf("Berechtigungen gespeichert; SMB-Verbindungen konnten nicht geschlossen werden. Samba neu starten: %w", err)
	}
	return clearSetting(ctx, m.db, disconnectKey)
}

// SyncPermissions publishes signatures only after successful ACL writes. It
// does not disconnect SMB clients; CloseDataConnections runs after commit.
func (m *Mutation) SyncPermissions(ctx context.Context, force bool) error {
	_, pending, err := readSetting(ctx, m.db, repairKey)
	if err != nil {
		return err
	}
	if pending {
		return Conflict("Unterbrochene Berechtigungsänderung zuerst wiederherstellen")
	}

	// A canceled forced pass can leave partly repaired ACLs even if all of
	// their prior signatures matched. Keep the same legacy recovery marker
	// rather than changing signatures for folders we did not reach.
	if err := addSetting(ctx, m.db, repairKey, "{}"); err != nil {
		return err
	}
	return writeTransaction(ctx, m.db, func(db database) error {
		if err := m.syncPermissions(ctx, db, force); err != nil {
			return err
		}
		return clearSetting(ctx, db, repairKey)
	})
}

func (s *Service) syncPermissions(ctx context.Context, db database, force bool) error {
	if s.cfg.ACLWriter == nil {
		return errors.New("managed Samba ACL writer is not configured")
	}
	shareRoot, err := sambaacl.NewDescriptor(nil, s.cfg.AdminSID, sambaacl.Options{Directory: true, ShareRoot: true})
	if err != nil {
		return err
	}
	if err := revokeExcluded(ctx, db); err != nil {
		return err
	}
	folders, err := readFolders(ctx, db, false)
	if err != nil {
		return err
	}
	active, err := openDirPath(s.cfg.GroupRoot, true)
	if err != nil {
		return err
	}
	defer active.Close()
	if err := s.cfg.ACLWriter.SetACLFD(ctx, active, shareRoot); err != nil {
		return err
	}

	force = force || (s.cfg.RepairACLs != nil && s.cfg.RepairACLs())
	for _, row := range folders {
		if err := ctx.Err(); err != nil {
			return err
		}
		name, err := s.folderComponent(row)
		if err != nil {
			return err
		}
		levels := map[string]int{}
		if row.Active {
			levels, err = effectiveLevels(ctx, db, row.ID)
			if err != nil {
				return err
			}
		}
		if err := s.syncFolder(ctx, db, active, row, name, levels, force); err != nil {
			return fmt.Errorf("sync ACLs for %q: %w", row.Name, err)
		}
	}
	return nil
}

func (s *Service) syncFolder(ctx context.Context, db database, active *os.File, row folderRow, name string, levels map[string]int, force bool) error {
	parent := active
	if !row.Active {
		archive, err := openDirPath(s.cfg.ArchiveRoot, true)
		if err != nil {
			return err
		}
		defer archive.Close()
		parent = archive
	}
	top, err := sambaacl.NewDescriptor(levels, s.cfg.AdminSID, sambaacl.Options{Directory: true, TopLevel: true})
	if err != nil {
		return err
	}
	folder, err := openEntry(parent, name, true, true)
	if err != nil {
		return err
	}
	defer folder.Close()
	if err := s.cfg.ACLWriter.SetACLFD(ctx, folder, top); err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(top.SDDL()))
	signature := hex.EncodeToString(digest[:])
	if !force && row.Signature == signature {
		return nil
	}
	dirACL, err := sambaacl.NewDescriptor(levels, s.cfg.AdminSID, sambaacl.Options{Directory: true})
	if err != nil {
		return err
	}
	fileACL, err := sambaacl.NewDescriptor(levels, s.cfg.AdminSID, sambaacl.Options{})
	if err != nil {
		return err
	}
	if err := s.walkACL(ctx, folder, dirACL, fileACL); err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, "UPDATE shares SET aclSignature=? WHERE objectGUID=?", signature, row.ID)
	return err
}

func (s *Service) walkACL(ctx context.Context, folder *os.File, dirACL, fileACL sambaacl.Descriptor) error {
	entries, err := folder.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		child, err := openEntry(folder, entry.Name(), false, false)
		if err != nil {
			return err
		}
		err = func() error {
			defer child.Close()
			info, err := child.Stat()
			if err != nil {
				return err
			}
			if info.IsDir() {
				if err := s.cfg.ACLWriter.SetACLFD(ctx, child, dirACL); err != nil {
					return err
				}
				return s.walkACL(ctx, child, dirACL, fileACL)
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("unsupported managed entry: %s", child.Name())
			}
			return s.cfg.ACLWriter.SetACLFD(ctx, child, fileACL)
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

// PrepareDataRestore is a trash.DataRestoreACL callback. Use only while the
// Mutation's lock is held across the entire trash restore including publication.
func (m *Mutation) PrepareDataRestore(ctx context.Context, target trash.DataRestoreTarget) error {
	parts := strings.Split(target.RelativePath, "/")
	if len(parts) < 2 || len(target.Directories) != len(parts)-1 || target.Source == nil || m.cfg.ACLWriter == nil {
		return Invalid("Wiederherstellung erfordert einen aktiven verwalteten Datenordner")
	}
	for _, part := range parts {
		if !basename(part) || strings.ContainsRune(part, '\\') {
			return Invalid("Ungültiger Wiederherstellungspfad")
		}
	}
	row, err := scanFolder(m.db.QueryRowContext(ctx, folderSelect+" WHERE shareName=? AND isActive=1", parts[0]))
	if errors.Is(err, sql.ErrNoRows) {
		return Invalid("Wiederherstellung erfordert einen aktiven verwalteten Datenordner")
	}
	if err != nil {
		return err
	}
	name, err := m.folderComponent(row)
	if err != nil || name != parts[0] {
		return errors.New("restore target does not match the stored folder path")
	}
	root, err := openDirPath(m.cfg.GroupRoot, false)
	if err != nil {
		return err
	}
	defer root.Close()
	parent := root
	for i, borrowed := range target.Directories {
		if borrowed == nil {
			return errors.New("nil pinned restore directory")
		}
		named, err := openEntry(parent, parts[i], true, false)
		if err != nil {
			return err
		}
		expected, statErr := named.Stat()
		named.Close()
		actual, err := borrowed.Stat()
		if statErr != nil || err != nil || !actual.IsDir() || !os.SameFile(expected, actual) {
			return errors.New("pinned restore directory no longer matches the managed path")
		}
		parent = borrowed
	}
	info, err := target.Source.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("restore source must be a pinned regular file")
	}
	levels, err := effectiveLevels(ctx, m.db, row.ID)
	if err != nil {
		return err
	}
	for i, borrowed := range target.Directories {
		d, err := sambaacl.NewDescriptor(levels, m.cfg.AdminSID, sambaacl.Options{Directory: true, TopLevel: i == 0})
		if err != nil {
			return err
		}
		if err := m.cfg.ACLWriter.SetACLFD(ctx, borrowed, d); err != nil {
			return err
		}
	}
	d, err := sambaacl.NewDescriptor(levels, m.cfg.AdminSID, sambaacl.Options{})
	if err != nil {
		return err
	}
	return m.cfg.ACLWriter.SetACLFD(ctx, target.Source, d)
}
