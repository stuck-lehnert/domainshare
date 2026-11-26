package backup

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

func timestamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05+00:00") }

type runLogger struct {
	stdout io.Writer
	stderr io.Writer
	file   *os.File
}

func newLogger(options Options) *runLogger {
	logger := &runLogger{stdout: options.Stdout, stderr: options.Stderr}
	if logger.stdout == nil {
		logger.stdout = os.Stdout
	}
	if logger.stderr == nil {
		logger.stderr = os.Stderr
	}
	if options.LogPath != "" {
		err := os.MkdirAll(filepath.Dir(options.LogPath), 0755)
		if err == nil {
			logger.file, err = os.OpenFile(options.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		}
		if err != nil {
			logger.warn("unable to open log file: %v", err)
		}
	}
	return logger
}

func (l *runLogger) close() {
	if l.file != nil {
		_ = l.file.Close()
	}
}

func (l *runLogger) warn(format string, args ...any) {
	fmt.Fprintf(l.stderr, "[backup] WARNING: "+format+"\n", args...)
}

func (l *runLogger) print(format string, args ...any) { l.log(true, format, args...) }

func (l *runLogger) log(console bool, format string, args ...any) {
	line := fmt.Sprintf("[backup] "+format+"\n", args...)
	if console {
		_, _ = io.WriteString(l.stdout, line)
	}
	if l.file != nil {
		_, _ = io.WriteString(l.file, timestamp(time.Now())+" "+line)
	}
}

type runStatus struct {
	path string
	data map[string]any
	log  *runLogger
}

func newStatus(path, destination, trigger string, log *runLogger) *runStatus {
	s := &runStatus{path: path, data: make(map[string]any), log: log}
	s.write(map[string]any{
		"enabled": true, "state": "starting", "trigger": trigger, "workerPid": os.Getpid(),
		"startedAt": timestamp(time.Now()), "finishedAt": nil, "destination": destination,
		"snapshot": nil, "currentSource": nil, "percent": 0, "transferredBytes": int64(0),
		"totalBytes": int64(0), "activeFiles": []fileProgress{}, "message": "Starting backup",
	})
	return s
}

func (s *runStatus) write(changes map[string]any) {
	if s == nil {
		return
	}
	for key, value := range changes {
		s.data[key] = value
	}
	s.data["updatedAt"] = timestamp(time.Now())
	if s.path == "" {
		return
	}

	data, err := json.Marshal(s.data)
	if err == nil {
		err = writeAtomic(s.path, data, false)
	}
	if err != nil {
		s.log.warn("unable to update status file: %v", err)
	}
}

func (s *runStatus) finish(ok bool, message string) {
	state := "failed"
	changes := map[string]any{
		"workerPid": nil, "finishedAt": timestamp(time.Now()),
		"activeFiles": []fileProgress{}, "message": message,
	}
	if ok {
		state = "completed"
		changes["percent"] = 100
		changes["transferredBytes"] = s.data["totalBytes"]
		changes["currentSource"] = nil
	}
	changes["state"] = state
	s.write(changes)
}

// writeAtomic ensures readers never see partially written status or journals.
// Persist the directory entry as well for the cleanup journal, before uploads.
func writeAtomic(path string, data []byte, durable bool) error {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(parent, ".backup-write-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	if !durable {
		return nil
	}
	directory, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
