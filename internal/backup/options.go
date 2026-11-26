// Package backup runs and restores DomainShare destination snapshots.
package backup

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultStatusPath = "/state/backup-status.json"
	DefaultLogPath    = "/var/log/backup.log"
)

// Source maps a local directory to its relative location in a snapshot. Run
// recognizes "state" and "data/groups" for the special staging rules.
type Source struct {
	Path        string
	Destination string
}

// Options holds a single run's configuration. Use OptionsFromEnv for the
// original production defaults and override fields where needed.
type Options struct {
	Destination string
	Namespace   string
	Encrypted   bool
	Password    string
	KeyID       string
	KeyFormat   string
	StateRoot   string
	StateDBPath string
	DocumentDir string
	ArchiveTemp string
	StatusPath  string
	LogPath     string
	Trigger     string

	Sources          []Source
	Retention        RetentionPolicy
	ProgressMode     string
	ProgressInterval time.Duration
	Stdout           io.Writer
	Stderr           io.Writer
}

// OptionsFromEnv reads the worker's existing environment contract. Lookup may
// read environment values directly or a configuration snapshot's overlay.
func OptionsFromEnv(lookup func(string) (string, bool)) Options {
	get := func(key, fallback string) string {
		if value, ok := lookup(key); ok {
			return value
		}
		return fallback
	}
	number := func(key string, fallback int, maximum int) int {
		val, err := strconv.Atoi(strings.TrimSpace(get(key, "")))
		if err != nil || val < 0 || (maximum > 0 && val > maximum) {
			return fallback
		}
		return val
	}
	state := get("STATE_ROOT", "/state")
	db := get("STATE_DB_PATH", get("SHARE_DB_PATH", filepath.Join(state, "shares.db")))
	interval := number("BACKUP_PROGRESS_INTERVAL_SECONDS", 10, 0)
	if interval == 0 || int64(interval) > (1<<63-1)/int64(time.Second) {
		interval = 10
	}
	trigger := strings.TrimSpace(get("BACKUP_TRIGGER", "manual"))
	if trigger == "" {
		trigger = "manual"
	}

	return Options{
		Destination: strings.TrimSpace(get("BACKUP_DESTINATION", "")),
		Namespace:   strings.Trim(get("BACKUP_NAMESPACE", ""), "/"),
		Encrypted:   strings.EqualFold(get("BACKUP_ENCRYPTION_ENABLED", "false"), "true"),
		Password:    get("BACKUP_ARCHIVE_PASSWORD", ""),
		KeyID:       get("BACKUP_KEY_ID", ""),
		KeyFormat:   get("BACKUP_KEY_FORMAT", "7z-aes256"),
		StateRoot:   state,
		StateDBPath: db,
		DocumentDir: get("DOCUMENT_STATE_ROOT", filepath.Join(state, "documents")),
		ArchiveTemp: strings.TrimSpace(get("BACKUP_ARCHIVE_TEMP_DIR", "/tmp")),
		StatusPath:  strings.TrimSpace(get("BACKUP_STATUS_FILE", DefaultStatusPath)),
		LogPath:     strings.TrimSpace(get("BACKUP_LOG_FILE", DefaultLogPath)),
		Trigger:     trigger,
		Sources: []Source{
			{"/data/private", "data/private"},
			{"/data/groups", "data/groups"},
			{"/data/fslogix", "data/fslogix"},
			{state, "state"},
			{"/var/lib/samba/private", "samba/private"},
		},
		Retention: RetentionPolicy{
			Daily:   number("BACKUP_RETENTION_DAILY", 3, 0),
			Weekly:  number("BACKUP_RETENTION_WEEKLY", 2, 0),
			Monthly: number("BACKUP_RETENTION_MONTHLY", 2, 0),
			Yearly:  number("BACKUP_RETENTION_YEARLY", 1, 0),
		},
		ProgressMode:     strings.ToLower(strings.TrimSpace(get("BACKUP_PROGRESS", "auto"))),
		ProgressInterval: time.Duration(interval) * time.Second,
		Stdout:           os.Stdout,
		Stderr:           os.Stderr,
	}
}

// LockPath is the cross-process flock shared with the original backup worker.
func LockPath(stateRoot string) string { return filepath.Join(stateRoot, "backup.lock") }
