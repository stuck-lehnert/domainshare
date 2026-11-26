package webapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/stuck-lehnert/domainshare/internal/backup"
	"github.com/stuck-lehnert/domainshare/internal/config"
	"golang.org/x/sys/unix"
)

func readRegularTail(path string, limit int64, tail bool) []byte {
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	cut := info.Size() > limit
	if cut {
		if !tail {
			return nil
		}
		if _, err := file.Seek(-limit, io.SeekEnd); err != nil {
			return nil
		}
	}

	data, err := io.ReadAll(io.LimitReader(file, limit))
	if err != nil {
		return nil
	}
	if cut {
		_, data, _ = bytes.Cut(data, []byte{'\n'})
	}
	return data
}

func statusFile(path string) map[string]any {
	var status map[string]any
	if json.Unmarshal(readRegularTail(path, 512*1024, false), &status) != nil || status == nil {
		return map[string]any{}
	}
	delete(status, "log")
	return status
}

func tailLines(path string, count int) []string {
	text := strings.TrimRight(string(readRegularTail(path, 256*1024, true)), "\r\n")
	if text == "" {
		return []string{}
	}
	lines := strings.Split(strings.ToValidUTF8(text, "\uFFFD"), "\n")
	return lines[max(0, len(lines)-count):]
}

func includeLog(params url.Values) bool {
	switch strings.ToLower(strings.TrimSpace(params.Get("log"))) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

func pathSetting(env map[string]string, key, fallback string) string {
	if path := env[key]; path != "" {
		return path
	}
	return fallback
}

func readBackupStatus(root, path string) map[string]any {
	value := statusFile(path)
	active := func() bool { return value["state"] == "running" || value["state"] == "starting" }
	value["processRunning"] = active()
	if !active() {
		return value
	}

	// Confirm a potentially interrupted job under the worker's flock. GET
	// must not overwrite a worker's durable status or journal.
	lock, err := backup.AcquireLock(root)
	if err != nil {
		return value
	}
	defer lock.Close()

	value = statusFile(path)
	value["processRunning"] = false
	if active() {
		value["state"], value["interrupted"] = "failed", true
		value["finishedAt"] = value["updatedAt"]
		value["workerPid"], value["currentSource"] = nil, nil
		value["activeFiles"] = []any{}
		value["message"] = "Backup interrupted because the worker process is no longer running"
	}
	return value
}

func backupStatus(snapshot config.Snapshot, env map[string]string, logs bool) map[string]any {
	root := env["STATE_ROOT"]
	path := pathSetting(env, "BACKUP_STATUS_FILE", filepath.Join(root, "backup-status.json"))
	value := readBackupStatus(root, path)
	configured := strings.TrimSpace(env["BACKUP_DESTINATION"]) != ""
	value["enabled"], value["manualEnabled"] = configured, configured
	value["automaticEnabled"] = configured && snapshot.Values.Bool("BACKUP_AUTO_ENABLED")
	value["scheduledHour"] = snapshot.Values.Int("BACKUP_START_HOUR")
	if value["state"] == nil {
		value["state"], value["percent"] = "disabled", 0
		if configured {
			value["state"] = "waiting"
		}
	}
	if logs {
		value["log"] = tailLines(pathSetting(env, "BACKUP_LOG_FILE", backup.DefaultLogPath), 100)
	}
	return value
}

func reconciliationStatus(env map[string]string, logs bool) map[string]any {
	path := pathSetting(env, "RECONCILE_STATUS_FILE", filepath.Join(env["STATE_ROOT"], "reconcile-status.json"))
	value := statusFile(path)
	if value["state"] == nil {
		value["state"], value["phase"], value["percent"] = "waiting", "waiting", 0
		value["message"] = "No reconciliation has run yet"
	}
	value["automaticEnabled"], value["scheduledIntervalMinutes"] = true, 5
	if logs {
		value["log"] = tailLines(pathSetting(env, "RECONCILE_LOG_FILE", "/var/log/reconcile.log"), 150)
	}
	return value
}

func (api AdminAPI) overview(w http.ResponseWriter, ctx context.Context, snapshot config.Snapshot, env map[string]string) {
	today := time.Now().UTC().Truncate(24 * time.Hour)
	query := url.Values{"limit": {"12"}, "facets": {"0"}}
	recent, err := api.Audit.QueryActivity(ctx, today.AddDate(0, 0, -1), today, query, "main")
	if err != nil {
		adminResult(w, nil, err)
		return
	}

	eventCount := any(recent.Matched)
	if recent.Matched == nil {
		eventCount = strconv.Itoa(len(recent.Events)) + "+"
	}
	var active int64
	_ = api.Usage.DB.QueryRowContext(ctx, `SELECT count(*) FROM shares WHERE isActive = 1`).Scan(&active)
	summary, _ := api.Audit.Summary(ctx, env["STATE_DB_PATH"])
	writeJSON(w, http.StatusOK, map[string]any{
		"usage": api.Usage.snapshot(ctx), "activeGroups": active, "recentEvents": recent.Events,
		"eventCount": eventCount, "backup": backupStatus(snapshot, env, true), "audit": summary,
	})
}
