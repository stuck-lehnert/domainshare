package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

const snapshotLayout = "20060102T150405Z"

func snapshotTime(name string) (time.Time, bool) {
	stamp, err := time.Parse(snapshotLayout, name)
	return stamp, err == nil && stamp.Year() > 0 && stamp.Format(snapshotLayout) == name
}

func validSnapshot(name string) bool {
	_, ok := snapshotTime(name)
	return ok
}

func snapshotNames(lines []string) []string {
	names := make([]string, 0, len(lines))
	seen := make(map[string]bool)
	for _, line := range lines {
		name := strings.TrimSuffix(strings.TrimSpace(line), "/")
		if validSnapshot(name) && !seen[name] {
			names = append(names, name)
			seen[name] = true
		}
	}
	sort.Strings(names)
	return names
}

func chooseSnapshotName(now time.Time, existing []string) (string, error) {
	seen := make(map[string]bool, len(existing))
	for _, name := range existing {
		seen[name] = true
	}
	for offset := range 120 {
		name := now.UTC().Add(time.Duration(offset) * time.Second).Format(snapshotLayout)
		if !seen[name] {
			return name, nil
		}
	}
	return "", errors.New("unable to generate a unique snapshot name")
}

// RetentionPolicy is the number of newest eligible snapshots to keep in each
// tier. A snapshot is retained if at least one tier selects it.
type RetentionPolicy struct {
	Daily, Weekly, Monthly, Yearly int
}

// RetainedSnapshots calculates retention over completed snapshot names. Weekly
// eligibility is Monday (UTC), monthly is the first, and yearly is January 1.
func RetainedSnapshots(names []string, policy RetentionPolicy) map[string]bool {
	names = snapshotNames(names)
	retained := make(map[string]bool)
	for i := len(names) - 1; i >= 0; i-- {
		name := names[i]
		stamp, _ := snapshotTime(name)
		if policy.Daily > 0 {
			retained[name] = true
			policy.Daily--
		}
		if policy.Weekly > 0 && stamp.Weekday() == time.Monday {
			retained[name] = true
			policy.Weekly--
		}
		if policy.Monthly > 0 && stamp.Day() == 1 {
			retained[name] = true
			policy.Monthly--
		}
		if policy.Yearly > 0 && stamp.Day() == 1 && stamp.Month() == time.January {
			retained[name] = true
			policy.Yearly--
		}
	}
	return retained
}

// pythonJSONString reproduces json.dumps' default ensure_ascii encoding for the
// local journal identifier, including Unicode surrogate pairs.
func pythonJSONString(value string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range value {
		switch r {
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			switch {
			case r >= 0x20 && r < 0x7f:
				b.WriteRune(r)
			case r <= 0xffff:
				fmt.Fprintf(&b, `\u%04x`, r)
			default:
				high, low := utf16.EncodeRune(r)
				fmt.Fprintf(&b, `\u%04x\u%04x`, high, low)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func journalPath(root string, d destination) string {
	port := "null"
	if d.port != 0 {
		port = strconv.Itoa(d.port)
	}
	parts := []string{pythonJSONString(d.scheme), pythonJSONString(d.host), port,
		pythonJSONString(d.user), pythonJSONString(strings.TrimRight(d.path, "/"))}
	digest := sha256.Sum256([]byte("[" + strings.Join(parts, ", ") + "]"))
	return filepath.Join(root, pendingDirectory, hex.EncodeToString(digest[:]))
}

func cleanupPending(ctx context.Context, b backend, path string, log *runLogger) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	name := strings.TrimSpace(string(data))
	if !validSnapshot(name) {
		return errors.New("invalid pending backup snapshot name; refusing cleanup")
	}

	entries, err := b.directories(ctx)
	if err != nil {
		return err
	}
	for _, existing := range entries {
		if name != existing {
			continue
		}
		complete, err := b.hasMarker(ctx, name)
		if err != nil {
			return err
		}
		if !complete {
			log.print("Removing incomplete snapshot %s", name)
			if err := b.deleteSnapshot(ctx, name); err != nil {
				return err
			}
		}
		break
	}
	return os.Remove(path)
}

func prune(ctx context.Context, b backend, policy RetentionPolicy, log *runLogger) (int, error) {
	directories, err := b.directories(ctx)
	if err != nil {
		return 0, err
	}
	var complete []string
	for _, name := range directories {
		marked, err := b.hasMarker(ctx, name)
		if err != nil {
			return 0, err
		}
		if marked {
			complete = append(complete, name)
		}
	}
	retained := RetainedSnapshots(complete, policy)
	for i := len(complete) - 1; i >= 0; i-- {
		name := complete[i]
		if !retained[name] {
			log.print("Pruning snapshot %s", name)
			if err := b.deleteSnapshot(ctx, name); err != nil {
				return 0, err
			}
		}
	}
	log.print("Backup completed (snapshots total=%d, retained=%d, pruned=%d)", len(complete), len(retained), len(complete)-len(retained))
	return len(retained), nil
}
