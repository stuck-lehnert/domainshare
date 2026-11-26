package trash

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

var ErrChanged = errors.New("Papierkorbeintrag wurde währenddessen verändert")

type openEntry struct {
	share, relative string
	parts           []string
	info            unix.Stat_t
	file            *os.File
	root            *os.File
	repository      *os.File
	parents         []*os.File
}

func (entry *openEntry) parent() *os.File {
	if len(entry.parents) == 0 {
		return entry.repository
	}
	return entry.parents[len(entry.parents)-1]
}

func (entry *openEntry) leaf() string { return entry.parts[len(entry.parts)-1] }

func (entry *openEntry) closeDirectories() {
	for _, parent := range entry.parents {
		_ = parent.Close()
	}
	if entry.repository != nil {
		_ = entry.repository.Close()
	}
	_ = entry.root.Close()
}

func (s *Service) openItem(ctx context.Context, id string) (*openEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	share, relative, err := DecodeItemID(id)
	if err != nil {
		return nil, err
	}
	if _, err := originalParts(relative); err != nil {
		return nil, err
	}
	parts := strings.Split(relative, "/") // Validated by DecodeItemID.
	if reservedStage(parts[0]) || ExcludedFilename(parts[len(parts)-1]) {
		return nil, &os.PathError{Op: "open trash item", Path: relative, Err: os.ErrNotExist}
	}

	root, err := openRoot(s.rootFor(share))
	if err != nil {
		return nil, err
	}
	entry := &openEntry{share: share, relative: relative, parts: parts, root: root}
	keepOpen := false
	defer func() {
		if !keepOpen {
			if entry.file != nil {
				_ = entry.file.Close()
			}
			entry.closeDirectories()
		}
	}()

	entry.repository, err = openDir(root, Directory)
	if err != nil {
		return nil, err
	}
	for _, name := range parts[:len(parts)-1] {
		parent, err := openDir(entry.parent(), name)
		if err != nil {
			return nil, err
		}
		entry.parents = append(entry.parents, parent)
	}

	parent, name := entry.parent(), entry.leaf()
	before, err := statEntry(parent, name)
	if err != nil {
		return nil, &os.PathError{Op: "stat trash item", Path: relative, Err: err}
	}
	if fileType(before) != unix.S_IFREG {
		return nil, InvalidError("Nur reguläre Dateien können verarbeitet werden")
	}
	fileFD, err := unix.Openat(fd(parent), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open trash item", Path: relative, Err: err}
	}
	entry.file = os.NewFile(uintptr(fileFD), name)
	entry.info, err = statFile(entry.file)
	if err != nil {
		return nil, err
	}
	if fileType(entry.info) != unix.S_IFREG || !sameInode(entry.info, before) {
		return nil, ErrChanged
	}
	if modTime(entry.info).Before(s.now(time.Time{}).Add(-s.retention())) {
		return nil, &os.PathError{Op: "open expired trash item", Path: relative, Err: os.ErrNotExist}
	}
	keepOpen = true
	return entry, nil
}

// OpenDownload returns the exact opened inode and metadata derived from it.
// The caller owns the file and must close it.
func (s *Service) OpenDownload(ctx context.Context, id string) (*os.File, Item, error) {
	entry, err := s.openItem(ctx, id)
	if err != nil {
		return nil, Item{}, err
	}
	defer entry.closeDirectories()
	item, err := itemPayload(entry.share, entry.relative, entry.info, s.retention())
	if err != nil {
		_ = entry.file.Close()
		return nil, Item{}, err
	}
	return entry.file, item, nil
}
