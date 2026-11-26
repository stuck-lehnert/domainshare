// Package accesscontrol manages individual Windows permissions on Data folders.
package accesscontrol

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/stuck-lehnert/domainshare/internal/sambaacl"
	"golang.org/x/sys/unix"
)

type Conflict string

func (e Conflict) Error() string { return string(e) }

type Invalid string

func (e Invalid) Error() string { return string(e) }

type Principal struct {
	SID, SAM, Name, DN string
	PrimaryRID         int
	Members            []string
}

type ACLWriter interface {
	SetACLFD(context.Context, *os.File, sambaacl.Descriptor) error
}

type Config struct {
	GroupRoot, ArchiveRoot, LockPath, AdminSID string
	ACLWriter                                  ACLWriter
	ReadDirectory                              func(context.Context, bool) (users, groups map[string]Principal, err error)
	CloseDataConnections                       func(context.Context) error
	RepairACLs                                 func() bool
	Logf                                       func(string, ...any)
}

type Service struct {
	db  *sql.DB
	cfg Config
}

// New configures a service without opening managed data or taking ownership of db.
func New(db *sql.DB, cfg Config) (*Service, error) {
	if db == nil {
		return nil, errors.New("access control needs the shared state database")
	}
	if cfg.GroupRoot == "" {
		cfg.GroupRoot = "/data/groups/data"
	}
	if cfg.ArchiveRoot == "" {
		cfg.ArchiveRoot = "/data/groups/archive"
	}
	if cfg.LockPath == "" {
		cfg.LockPath = "/state/reconcile.lock"
	}
	for _, path := range []*string{&cfg.GroupRoot, &cfg.ArchiveRoot, &cfg.LockPath} {
		if !filepath.IsAbs(*path) || filepath.Clean(*path) == "/" {
			return nil, fmt.Errorf("managed paths must be absolute and non-root: %q", *path)
		}
		*path = filepath.Clean(*path)
	}
	if cfg.GroupRoot == cfg.ArchiveRoot || filepath.Dir(cfg.GroupRoot) != filepath.Dir(cfg.ArchiveRoot) {
		return nil, errors.New("managed Data and archive roots must be distinct sibling directories")
	}
	return &Service{db: db, cfg: cfg}, nil
}

func (s *Service) EnsureSchema(ctx context.Context) error {
	return writeTransaction(ctx, s.db, func(db database) error { return ensureSchema(ctx, db) })
}

type mutationService = Service

// Mutation borrows the shared reconciliation lock for the callback lifetime.
// It must not escape the callback or be used concurrently.
type Mutation struct{ *mutationService }

// WithMutation uses the same advisory lock as Python and returns Conflict if
// another process currently holds it. Its callback must not reacquire the lock.
func (s *Service) WithMutation(ctx context.Context, work func(*Mutation) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if work == nil {
		return errors.New("nil access-control mutation")
	}

	parent, err := openDirPath(filepath.Dir(s.cfg.LockPath), true)
	if err != nil {
		return err
	}
	defer parent.Close()
	fd, err := unix.Openat(int(parent.Fd()), filepath.Base(s.cfg.LockPath),
		unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return fmt.Errorf("open reconciliation lock: %w", err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		return errors.New("invalid reconciliation lock file")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return Conflict("Freigabenabgleich läuft; bitte erneut versuchen")
		}
		return fmt.Errorf("lock managed folder reconciliation: %w", err)
	}
	defer unix.Flock(fd, unix.LOCK_UN)

	if err := s.EnsureSchema(ctx); err != nil {
		return err
	}
	return work(&Mutation{s})
}

func (s *Service) logf(format string, args ...any) {
	if s.cfg.Logf != nil {
		s.cfg.Logf(format, args...)
	}
}
