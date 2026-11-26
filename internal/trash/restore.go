package trash

import (
	"context"
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

var ErrDataACLRequired = errors.New("Data restore requires current ACL preparation")

// DataRestoreTarget contains borrowed descriptors for the exact file and
// directories involved in restoring to Data. Directories starts at the existing
// managed group directory and ends at the destination's parent. Descriptors
// remain owned by Restore and must not be retained or closed by the callback.
type DataRestoreTarget struct {
	RelativePath string
	Source       *os.File
	Directories  []*os.File
}

// DataRestoreACL validates an active managed folder and installs its current
// ACL on the supplied inodes. The caller holds the shared ACL mutation lock
// throughout Restore and can look up policy through its shares.db connection.
// It must report any ACL or ownership failure; there is no mode-only fallback.
type DataRestoreACL func(context.Context, DataRestoreTarget) error

type RestoreResult struct {
	Restored bool   `json:"restored"`
	Share    string `json:"share"`
	Path     string `json:"path"`
}

type pinnedParent struct {
	parent  *os.File
	file    *os.File
	name    string
	info    unix.Stat_t
	created bool
}

// Restore publishes the same inode at its original location, without replacing
// anything. Data's top-level folder must already exist; missing descendants are
// initially private (0700) until ACL preparation. On failure, only unchanged,
// empty parents created by this call are removed, deepest first. Existing
// directories and directories with newly added user files are kept.
func (s *Service) Restore(ctx context.Context, id string, prepare DataRestoreACL) (_ RestoreResult, err error) {
	share, _, err := DecodeItemID(id)
	if err != nil {
		return RestoreResult{}, err
	}
	if share == "Data" && prepare == nil {
		return RestoreResult{}, ErrDataACLRequired
	}

	entry, err := s.openItem(ctx, id)
	if err != nil {
		return RestoreResult{}, err
	}
	defer entry.closeDirectories()
	defer entry.file.Close()

	original, err := originalParts(entry.relative)
	if err != nil {
		return RestoreResult{}, err
	}
	path := strings.Join(original, "/")
	if _, err := pathParts(path); err != nil || strings.EqualFold(original[0], Directory) {
		return RestoreResult{}, InvalidError("Ungültiger Wiederherstellungspfad")
	}
	if share == "Data" && len(original) < 2 {
		return RestoreResult{}, InvalidError("Wiederherstellung erfordert einen aktiven verwalteten Datenordner")
	}

	stage, err := newRestoreStage(entry.repository)
	if err != nil {
		return RestoreResult{}, err
	}
	defer stage.close()

	parents := make([]pinnedParent, 0, len(original)-1)
	published := false
	defer func() { releaseParents(parents, published) }()
	destination := entry.root
	for i, name := range original[:len(original)-1] {
		if err := ctx.Err(); err != nil {
			return RestoreResult{}, err
		}
		allowCreate := share != "Data" || i > 0
		parent, err := destinationParent(stage, destination, name, entry, allowCreate)
		if err != nil {
			return RestoreResult{}, err
		}
		parents = append(parents, parent)
		destination = parent.file
	}

	leaf := original[len(original)-1]
	if err := checkVacant(destination, leaf); err != nil {
		return RestoreResult{}, err
	}
	if err := stage.capture(entry); err != nil {
		return RestoreResult{}, err
	}
	// Every failure after capture (including ACL preparation) returns the
	// original inode to trash unless it has already been published.
	defer func() {
		if !published {
			err = stage.putBack(entry, err)
		}
	}()

	if share == "Data" {
		info, err := statFile(entry.file)
		if err != nil {
			return RestoreResult{}, err
		}
		// ACL mutation must not change another name for the same inode.
		if info.Nlink != 1 {
			return RestoreResult{}, InvalidError("Dateien mit mehreren Hardlinks können nicht nach Data wiederhergestellt werden")
		}
		directories := make([]*os.File, 0, len(parents))
		for _, parent := range parents {
			directories = append(directories, parent.file)
		}
		target := DataRestoreTarget{RelativePath: path, Source: entry.file, Directories: directories}
		if err := prepare(ctx, target); err != nil {
			return RestoreResult{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return RestoreResult{}, err
	}
	for _, parent := range parents {
		if !sameEntry(parent.parent, parent.name, parent.info) {
			return RestoreResult{}, ErrChanged
		}
	}

	if err := unix.Renameat2(fd(stage.file), "item", fd(destination), leaf, unix.RENAME_NOREPLACE); err != nil {
		return RestoreResult{}, &os.PathError{Op: "publish restored item", Path: path, Err: err}
	}
	published = true

	entry.pruneEmptyParents()
	return RestoreResult{Restored: true, Share: share, Path: path}, nil
}

func checkVacant(directory *os.File, name string) error {
	if _, err := statEntry(directory, name); err == nil {
		return &os.PathError{Op: "restore", Path: name, Err: unix.EEXIST}
	} else if !errors.Is(err, unix.ENOENT) {
		return err
	}
	return nil
}

func destinationParent(stage *restoreStage, directory *os.File, name string, entry *openEntry, create bool) (pinnedParent, error) {
	parent := pinnedParent{parent: directory, name: name}
	opened, err := openDir(directory, name)
	if errors.Is(err, unix.ENOENT) && create {
		opened, err = stage.makeParent(directory, name, entry)
		if err == nil {
			parent.created = true
		} else if errors.Is(err, unix.EEXIST) {
			// A concurrent request created it first. Treat it as pre-existing.
			opened, err = openDir(directory, name)
		}
	}
	if err != nil {
		return pinnedParent{}, err
	}
	info, err := statFile(opened)
	if err != nil {
		_ = opened.Close()
		return pinnedParent{}, err
	}
	parent.file, parent.info = opened, info
	return parent, nil
}

func releaseParents(parents []pinnedParent, keep bool) {
	for i := len(parents) - 1; i >= 0; i-- {
		parent := parents[i]
		if !keep && parent.created && sameEntry(parent.parent, parent.name, parent.info) {
			_ = unix.Unlinkat(fd(parent.parent), parent.name, unix.AT_REMOVEDIR)
		}
		_ = parent.file.Close()
	}
}

func (entry *openEntry) pruneEmptyParents() {
	for i := len(entry.parents) - 1; i >= 0; i-- {
		parent := entry.repository
		if i > 0 {
			parent = entry.parents[i-1]
		}
		info, err := statFile(entry.parents[i])
		if err != nil || !sameEntry(parent, entry.parts[i], info) {
			break
		}
		if err := unix.Unlinkat(fd(parent), entry.parts[i], unix.AT_REMOVEDIR); err != nil {
			break
		}
	}
}
