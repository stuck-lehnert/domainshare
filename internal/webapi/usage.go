package webapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/stuck-lehnert/domainshare/internal/directory"
	"github.com/stuck-lehnert/domainshare/internal/trash"
	"golang.org/x/text/cases"
)

type usageGroup struct {
	Name  string `json:"name"`
	Bytes int64  `json:"bytes"`
}

type usageUser struct {
	Name    string `json:"name"`
	Private int64  `json:"privateBytes"`
	FSLogix int64  `json:"fslogixBytes"`
	Total   int64  `json:"totalBytes"`
}

type usageTotals struct {
	Data    int64 `json:"dataBytes"`
	Private int64 `json:"privateBytes"`
	FSLogix int64 `json:"fslogixBytes"`
}

type usageReport struct {
	ScannedAt   *time.Time   `json:"scannedAt"`
	ScanSeconds float64      `json:"scanSeconds"`
	Groups      []usageGroup `json:"groups"`
	Users       []usageUser  `json:"users"`
	Totals      usageTotals  `json:"totals"`
}

type UsageScanner struct {
	DB                     *sql.DB
	Data, Private, FSLogix string
	Interval               time.Duration
}

func (s UsageScanner) EnsureSchema(ctx context.Context) error {
	_, err := s.DB.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS web_cache (
		key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)`)
	return err
}

func (s UsageScanner) snapshot(ctx context.Context) usageReport {
	report := usageReport{Groups: []usageGroup{}, Users: []usageUser{}}
	var raw string
	var cached usageReport
	if s.DB.QueryRowContext(ctx, `SELECT value FROM web_cache WHERE key='usage'`).Scan(&raw) != nil ||
		json.Unmarshal([]byte(raw), &cached) != nil {
		return report
	}

	report = cached
	report.Groups = append([]usageGroup{}, cached.Groups...)
	report.Users = []usageUser{}
	for _, row := range cached.Users {
		if !directory.IsExcludedUser(row.Name) {
			report.Users = append(report.Users, row)
		}
	}
	return report
}

func (s UsageScanner) Run(ctx context.Context) {
	interval := s.Interval
	if interval < time.Minute || interval > 24*time.Hour {
		interval = 15 * time.Minute
	}

	for ctx.Err() == nil {
		if err := s.scan(ctx); err != nil && ctx.Err() == nil {
			log.Printf("storage usage scan failed: %v", err)
		}

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (s UsageScanner) scan(ctx context.Context) error {
	started := time.Now()
	report := usageReport{Groups: []usageGroup{}, Users: []usageUser{}}
	users := map[string]*usageUser{}
	owners := map[uint32]string{}
	fold := cases.Fold()

	roots := []struct{ kind, path string }{
		{"data", s.Data}, {"private", s.Private}, {"fslogix", s.FSLogix},
	}
	for _, root := range roots {
		err := scanUsage(ctx, root.path, func(name string, uid uint32, size int64) {
			if root.kind == "data" {
				report.Groups = append(report.Groups, usageGroup{Name: name, Bytes: size})
				report.Totals.Data += size
				return
			}
			if root.kind == "fslogix" {
				owner, cached := owners[uid]
				if !cached {
					owner = usageOwner(ctx, uid)
					owners[uid] = owner
				}
				if owner != "" {
					name = owner
				} else if short := fslogixSuffix.ReplaceAllString(name, ""); short != "" {
					name = short
				}
			}

			key := fold.String(name)
			if users[key] == nil {
				users[key] = &usageUser{Name: name}
			}
			if root.kind == "private" {
				users[key].Private = size
			} else {
				users[key].FSLogix += size
			}
		})
		if err != nil {
			return err
		}
	}

	for _, user := range users {
		user.Total = user.Private + user.FSLogix
		report.Totals.Private += user.Private
		report.Totals.FSLogix += user.FSLogix
		if !directory.IsExcludedUser(user.Name) {
			report.Users = append(report.Users, *user)
		}
	}
	sort.Slice(report.Groups, func(i, j int) bool {
		a, b := report.Groups[i], report.Groups[j]
		if a.Bytes == b.Bytes {
			return fold.String(a.Name) < fold.String(b.Name)
		}
		return a.Bytes > b.Bytes
	})
	sort.Slice(report.Users, func(i, j int) bool {
		a, b := report.Users[i], report.Users[j]
		if a.Total == b.Total {
			return fold.String(a.Name) < fold.String(b.Name)
		}
		return a.Total > b.Total
	})

	stamp := time.Now().UTC().Truncate(time.Second)
	report.ScannedAt = &stamp
	report.ScanSeconds = time.Since(started).Round(time.Millisecond).Seconds()
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}

	_, err = s.DB.ExecContext(ctx, `INSERT INTO web_cache(key,value,updated_at) VALUES('usage',?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`, string(raw), stamp.Format(time.RFC3339))
	return err
}

var fslogixSuffix = regexp.MustCompile(`(?i)_S-1-\d+(?:-\d+)+$`)

func usageOwner(ctx context.Context, uid uint32) string {
	if uid == 0 || uid == 65534 {
		return ""
	}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "getent", "passwd", strconv.FormatUint(uint64(uid), 10)).Output()
	if err != nil {
		return ""
	}

	name, _, _ := strings.Cut(string(output), ":")
	name = name[strings.LastIndexByte(name, '\\')+1:]
	_, numeric := strconv.ParseUint(name, 10, 64)
	if strings.EqualFold(name, "root") || strings.EqualFold(name, "nobody") || numeric == nil {
		return ""
	}
	return name
}

func scanUsage(ctx context.Context, path string, add func(string, uint32, int64)) error {
	root, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	defer root.Close()

	tree := root.FS()
	entries, err := fs.ReadDir(tree, ".")
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.Name() == trash.Directory || !entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.IsDir() {
			continue
		}

		var size int64
		err = fs.WalkDir(tree, entry.Name(), func(_ string, child fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			if err != nil || !child.Type().IsRegular() {
				return err
			}

			info, err := child.Info()
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			if err == nil && info.Mode().IsRegular() {
				size += info.Size()
			}
			return err
		})
		if err != nil {
			return err
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			add(entry.Name(), stat.Uid, size)
		}
	}
	return nil
}
