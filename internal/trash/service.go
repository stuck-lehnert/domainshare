// Package trash manages Samba recycle bins. Authorization, ACL transactions,
// and audit logging belong to the caller (the authenticated web service).
package trash

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/text/cases"
)

const (
	DefaultRetentionDays = 7
	DefaultLimit         = 200
)

type Options struct {
	DataRoot, PrivateRoot, FSLogixRoot string
	RetentionDays                      int
	// Now is optional. It permits a caller to use the same clock for expiry,
	// download and restore, overriding time.Now when supplied.
	Now func() time.Time
}

func OptionsFromEnv(lookup func(string) (string, bool)) Options {
	get := func(key, fallback string) string {
		if value, ok := lookup(key); ok {
			return value
		}
		return fallback
	}
	days, err := strconv.Atoi(strings.TrimSpace(get("TRASH_RETENTION_DAYS", "7")))
	if err != nil {
		days = DefaultRetentionDays
	}
	return Options{
		DataRoot:      get("GROUP_ROOT", "/data/groups/data"),
		PrivateRoot:   get("PRIVATE_ROOT", "/data/private"),
		FSLogixRoot:   get("FSLOGIX_ROOT", "/data/fslogix"),
		RetentionDays: max(1, min(365, days)),
	}
}

type Service struct{ options Options }

func New(options Options) (*Service, error) {
	for _, root := range []*string{&options.DataRoot, &options.PrivateRoot, &options.FSLogixRoot} {
		if *root == "" {
			return nil, errors.New("all three trash share roots must be configured")
		}
		absolute, err := filepath.Abs(*root)
		if err != nil {
			return nil, err
		}
		*root = absolute
	}
	if options.RetentionDays == 0 {
		options.RetentionDays = DefaultRetentionDays
	}
	options.RetentionDays = max(1, min(365, options.RetentionDays))
	if options.Now == nil {
		options.Now = time.Now
	}
	return &Service{options: options}, nil
}

type shareRoot struct{ name, path string }

func (s *Service) roots() [3]shareRoot {
	return [...]shareRoot{{"Data", s.options.DataRoot}, {"Private", s.options.PrivateRoot}, {"FSLogix", s.options.FSLogixRoot}}
}

func (s *Service) rootFor(share string) string {
	for _, root := range s.roots() {
		if root.name == share {
			return root.path
		}
	}
	return ""
}

func (s *Service) now(value time.Time) time.Time {
	if !value.IsZero() {
		return value
	}
	return s.options.Now().UTC()
}

func (s *Service) retention() time.Duration {
	return time.Duration(s.options.RetentionDays) * 24 * time.Hour
}

func (s *Service) EnsureRoots(ctx context.Context) error {
	for _, root := range s.roots() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := ensureRepository(root.path); err != nil {
			return err
		}
	}
	return nil
}

type ListOptions struct {
	Share, Path string
	// Zero uses DefaultLimit. Explicit web API limit=0 should be clamped to 1.
	Limit int
	Now   time.Time
}

type ListResult struct {
	Items         []Item `json:"items"`
	Matched       int    `json:"matched"`
	Truncated     bool   `json:"truncated"`
	RetentionDays int    `json:"retentionDays"`
	ScannedAt     string `json:"scannedAt"`
}

func (s *Service) List(ctx context.Context, options ListOptions) (ListResult, error) {
	selected := options.Share
	if selected != "" {
		var err error
		selected, err = canonicalShare(selected)
		if err != nil {
			return ListResult{}, err
		}
	}
	limit := options.Limit
	if limit == 0 {
		limit = DefaultLimit
	}
	limit = max(1, min(500, limit))

	current := s.now(options.Now)
	retention := s.retention()
	cutoff := current.Add(-retention)
	fold := cases.Fold()
	filter := fold.String(strings.TrimSpace(options.Path))
	result := ListResult{Items: make([]Item, 0), RetentionDays: s.options.RetentionDays, ScannedAt: current.Format(timestampLayout)}

	for _, root := range s.roots() {
		if selected != "" && selected != root.name {
			continue
		}
		repository, err := openRepository(root.path)
		if err != nil {
			continue // Like os.walk, an unavailable share is not listed.
		}
		visit := func(_ *os.File, name, relative string, info unix.Stat_t) {
			if fileType(info) != unix.S_IFREG || modTime(info).Before(cutoff) || ExcludedFilename(name) {
				return
			}
			item, err := itemPayload(root.name, relative, info, retention)
			if err == nil && (filter == "" || strings.Contains(fold.String(item.Path), filter)) {
				result.Items = append(result.Items, item)
			}
		}
		err = walkRepository(ctx, repository, "", visit, false)
		_ = repository.Close()
		if err != nil {
			return ListResult{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return ListResult{}, err
	}

	sort.Slice(result.Items, func(i, j int) bool {
		a, b := result.Items[i], result.Items[j]
		if a.DeletedAt == b.DeletedAt {
			return a.ID > b.ID
		}
		return a.DeletedAt > b.DeletedAt
	})
	result.Matched = len(result.Items)
	result.Truncated = result.Matched > limit
	result.Items = result.Items[:min(result.Matched, limit)]
	return result, nil
}

type CleanupResult struct {
	Removed      int   `json:"removed"`
	RemovedBytes int64 `json:"removedBytes"`
}

// Cleanup removes expired and transient entries, followed by empty folders.
// It never follows a symlink in a share. Like the original timer, an entry
// that cannot be examined or removed is skipped rather than counted.
func (s *Service) Cleanup(ctx context.Context, now time.Time) (CleanupResult, error) {
	if err := s.EnsureRoots(ctx); err != nil {
		return CleanupResult{}, err
	}
	cutoff := s.now(now).Add(-s.retention())
	var result CleanupResult
	visit := func(parent *os.File, name, _ string, info unix.Stat_t) {
		switch fileType(info) {
		case unix.S_IFDIR:
			if sameEntry(parent, name, info) {
				_ = unix.Unlinkat(fd(parent), name, unix.AT_REMOVEDIR)
			}
		case unix.S_IFREG, unix.S_IFLNK:
			if !modTime(info).Before(cutoff) && !ExcludedFilename(name) {
				return
			}
			if sameEntry(parent, name, info) && unix.Unlinkat(fd(parent), name, 0) == nil {
				result.Removed++
				if fileType(info) == unix.S_IFREG {
					result.RemovedBytes += info.Size
				}
			}
		}
	}
	for _, root := range s.roots() {
		repository, err := openRepository(root.path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return result, err
		}
		err = walkRepository(ctx, repository, "", visit, true)
		_ = repository.Close()
		if err != nil {
			return result, err
		}
	}
	return result, ctx.Err()
}
