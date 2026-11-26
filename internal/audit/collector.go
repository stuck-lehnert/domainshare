package audit

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	payloadDate = regexp.MustCompile(`^\s*\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\|`)
	sambaDate   = regexp.MustCompile(`^\s*\[?(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})`)
)

// ParseLine accepts a Samba full_audit message or a timestamped payload on
// the second line of a Samba log entry. Unsupported operations are ignored.
func ParseLine(line, source string, observed time.Time) (Event, bool) {
	return parseLine(line, source, observed, skippedSuffixes())
}

func parseLine(line, source string, observed time.Time, suffixes []string) (Event, bool) {
	line = strings.TrimRight(line, "\r\n")
	var payload string
	if _, message, found := strings.Cut(line, "smbd_audit:"); found {
		payload = strings.TrimLeft(message, " \t\r\n\v\f")
	} else if payloadDate.MatchString(line) {
		payload = strings.TrimSpace(line)
	} else {
		return Event{}, false
	}

	fields := strings.SplitN(payload, "|", 8)
	if len(fields) < 8 {
		return Event{}, false
	}
	for i := range fields[1:] {
		fields[i+1] = strings.TrimSpace(fields[i+1])
	}
	user, operation := fields[1], fields[5]
	action := actionFor(operation)
	if action == "" || skipUser(user, suffixes) {
		return Event{}, false
	}

	observed = observed.UTC()
	ingestedAt := observed.Format(millisecondLayout)
	timestamp := ingestedAt
	if match := sambaDate.FindStringSubmatch(line); len(match) == 2 {
		value := strings.Join(strings.Fields(match[1]), " ")
		if parsed, err := time.Parse("2006/01/02 15:04:05", value); err == nil && parsed.Year() > 0 {
			timestamp = parsed.Format(secondLayout)
		}
	}
	return Event{
		Timestamp: timestamp, IngestedAt: ingestedAt, User: user,
		ClientIP: fields[2], Client: fields[3], Share: fields[4],
		Operation: operation, Action: action, Result: fields[6], Success: strings.ToUpper(fields[6]) == "OK",
		Path: fields[7], Source: filepath.Base(source),
	}, true
}

const (
	defaultSourceGlob = "/var/log/samba/log.*"
	defaultPoll       = time.Second
	minimumPoll       = 200 * time.Millisecond
)

// Collector tails the Samba logs. Run only one collector process per database.
// The collector is not started by Store and does not remove old archives.
type Collector struct {
	Store        *Store
	SourceGlob   string
	PollInterval time.Duration
	Logf         func(string, ...any)

	mu sync.Mutex
}

// NewCollector reads the legacy collector environment settings. Legacy file
// cleanup remains a separate explicit action via DropLegacyAuditFiles.
func NewCollector(store *Store) (*Collector, error) {
	return NewCollectorWithEnv(store, os.LookupEnv)
}

func NewCollectorWithEnv(store *Store, lookup func(string) (string, bool)) (*Collector, error) {
	get := func(key, fallback string) string {
		if value, ok := lookup(key); ok && strings.TrimSpace(value) != "" {
			return value
		}
		return fallback
	}
	glob := get("AUDIT_SOURCE_GLOB", defaultSourceGlob)
	poll, err := strconv.ParseFloat(strings.TrimSpace(get("AUDIT_POLL_SECONDS", "1")), 64)
	if err != nil || math.IsNaN(poll) || math.IsInf(poll, 0) || poll >= float64(math.MaxInt64)/float64(time.Second) {
		return nil, fmt.Errorf("invalid AUDIT_POLL_SECONDS")
	}
	interval := minimumPoll
	if poll >= minimumPoll.Seconds() {
		interval = time.Duration(poll * float64(time.Second))
	}
	return &Collector{Store: store, SourceGlob: glob, PollInterval: interval}, nil
}

type candidateFile struct {
	path  string
	mtime time.Time
	known bool
}

func fileInode(info os.FileInfo) (int64, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("file does not report a Unix inode")
	}
	return int64(stat.Ino), nil
}

func (c *Collector) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
		return
	}
	log.Printf("[audit] "+format, args...)
}

func (c *Collector) glob() string {
	if c.SourceGlob == "" {
		return defaultSourceGlob
	}
	return c.SourceGlob
}

// CollectOnce appends complete lines, preserving offsets across polls and
// using a rotated file's inode to resume it before ingesting a new active file.
func (c *Collector) CollectOnce(ctx context.Context) (int, error) {
	if c.Store == nil {
		return 0, errors.New("audit collector requires a store")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	state, err := c.Store.SourceEntries(ctx)
	if err != nil {
		return 0, err
	}
	byInode := make(map[int64]Source)
	for _, entry := range state {
		if existing, ok := byInode[entry.Inode]; entry.Inode >= 0 && (!ok || existing.Offset < entry.Offset) {
			byInode[entry.Inode] = entry
		}
	}

	paths, err := filepath.Glob(c.glob())
	if err != nil {
		return 0, fmt.Errorf("audit source glob: %w", err)
	}
	candidates := make([]candidateFile, 0, len(paths))
	seen := make(map[string]bool)
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			// Keep the previous offset when a transient error prevents inspection.
			if !errors.Is(err, os.ErrNotExist) {
				seen[path] = true
				c.logf("Unable to inspect %s: %v", path, err)
			}
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}
		seen[path] = true
		inode, err := fileInode(info)
		if err != nil {
			c.logf("Unable to inspect %s: %v", path, err)
			continue
		}
		_, known := byInode[inode]
		candidates = append(candidates, candidateFile{path, info.ModTime(), known})
	}
	slices.SortFunc(candidates, func(a, b candidateFile) int {
		if a.known != b.known {
			if a.known {
				return -1
			}
			return 1
		}
		if order := a.mtime.Compare(b.mtime); order != 0 {
			return order
		}
		return strings.Compare(a.path, b.path)
	})

	var events []Event
	updates := make(map[string]Source)
	suffixes := skippedSuffixes()
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		path := candidate.path
		found, entry, err := readNewEvents(ctx, path, state[path], byInode, suffixes)
		if err != nil {
			c.logf("Unable to read %s: %v", path, err)
			continue
		}
		events = append(events, found...)
		updates[path] = entry
	}
	return c.Store.AppendBatch(ctx, events, updates, seen)
}

func readNewEvents(ctx context.Context, path string, previous Source, byInode map[int64]Source, suffixes []string) ([]Event, Source, error) {
	// Nonblocking open also protects against a file being replaced with a FIFO
	// between the directory scan and open. The target must still be regular.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, Source{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, Source{}, err
	}
	if !info.Mode().IsRegular() {
		return nil, Source{}, errors.New("not a regular file")
	}
	inode, err := fileInode(info)
	if err != nil {
		return nil, Source{}, err
	}
	if inode != previous.Inode {
		previous = byInode[inode]
	}
	offset := previous.Offset
	if offset < 0 || offset > info.Size() {
		offset = 0
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, Source{}, err
	}

	var events []Event
	reader := bufio.NewReader(file)
	for {
		if err := ctx.Err(); err != nil {
			return nil, Source{}, err
		}
		line, err := reader.ReadString('\n')
		if errors.Is(err, io.EOF) {
			// A trailing partial record is read again once it reaches a newline.
			break
		}
		if err != nil {
			return nil, Source{}, err
		}
		offset += int64(len(line))
		if event, ok := parseLine(strings.ToValidUTF8(line, "\uFFFD"), path, time.Now(), suffixes); ok {
			events = append(events, event)
		}
	}
	return events, Source{Inode: inode, Offset: offset}, nil
}

// Run collects until ctx is canceled. Failed poll cycles are logged and
// retried without advancing source offsets past uncommitted events.
func (c *Collector) Run(ctx context.Context) error {
	if c.Store == nil {
		return errors.New("audit collector requires a store")
	}
	if _, err := filepath.Glob(c.glob()); err != nil {
		return fmt.Errorf("audit source glob: %w", err)
	}
	interval := c.PollInterval
	if interval == 0 {
		interval = defaultPoll
	}
	interval = max(minimumPoll, interval)
	c.logf("Watching %s; storing events in SQLite", c.glob())
	for ctx.Err() == nil {
		count, err := c.CollectOnce(ctx)
		if count != 0 {
			c.logf("Stored %d event(s)", count)
		}
		var backfilled int
		if err == nil {
			backfilled, err = c.Store.BackfillRollups(ctx, 5000)
		}
		if err != nil && ctx.Err() == nil {
			c.logf("Collector cycle failed: %v", err)
		}
		if backfilled != 0 {
			continue
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	return nil
}

// DropLegacyAuditFiles explicitly removes only the names matched by the old
// collector's cleanup policy. Store and Collector never call it implicitly.
func DropLegacyAuditFiles(dir string) (int, error) {
	if dir == "" {
		return 0, errors.New("an explicit legacy audit directory is required")
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	removed := 0
	patterns := []string{"????-??-??.jsonl", "????-??-??.jsonl.gz", "collector-state.json", "collector-state.json.tmp"}
	for _, entry := range entries {
		matched := slices.ContainsFunc(patterns, func(pattern string) bool {
			ok, _ := filepath.Match(pattern, entry.Name())
			return ok
		})
		if !matched || entry.IsDir() || !entry.Type().IsRegular() {
			continue
		}
		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
			return removed, err
		}
		removed++
	}
	// Match Python's rmdir behavior without risking deletion of a nonempty dir.
	_ = syscall.Rmdir(dir)
	return removed, nil
}
