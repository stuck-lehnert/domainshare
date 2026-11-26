package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	trashDirectory    = ".trash"
	officeLockPattern = "~$*"
)

func excludesRootTrash(destination string) bool {
	switch destination {
	case "data/private", "data/groups", "data/fslogix":
		return true
	}
	return false
}

func validatePassword(password string) error {
	if strings.ContainsAny(password, "\r\n\x00") {
		return errors.New("archive password contains unsupported characters")
	}
	return nil
}

var missingWarning = regexp.MustCompile(`^WARNING: (?:errno=2\s*:\s*)?No such file or directory$`)

func onlyMissingWarnings(output string) bool {
	var lines []string
	for _, line := range strings.Split(output, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 || len(lines)%2 != 0 {
		return false
	}
	for i := 0; i < len(lines); i += 2 {
		if !missingWarning.MatchString(lines[i]) {
			return false
		}
	}
	return true
}

func makeArchive(ctx context.Context, source, archive, password string, log *runLogger) (bool, error) {
	if err := validatePassword(password); err != nil {
		return false, err
	}
	archive, err := filepath.Abs(archive)
	if err != nil {
		return false, err
	}
	base := filepath.Base(source)
	if strings.ContainsAny(base, "*?") {
		return false, fmt.Errorf("unsupported wildcard in archive source directory name: %q", base)
	}

	args := []string{"a", "-t7z", "-m0=lzma2", "-mx=5", "-mmt=on", "-ms=off"}
	if password != "" {
		args = append(args, "-mhe=on", "-p")
	}
	args = append(args, "-snl", "-xr!"+trashDirectory, "-xr!"+officeLockPattern, "-y", archive, "--", "./"+base)

	cmd := exec.CommandContext(ctx, "7z", args...)
	cmd.Dir = filepath.Dir(source)
	cmd.Env = append(os.Environ(), "LC_ALL=C.UTF-8")
	if password != "" {
		cmd.Stdin = strings.NewReader(password + "\n")
	}
	result := runCaptured(cmd)
	if result.err == nil {
		return true, nil
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}

	missing := result.code() == 1 && onlyMissingWarnings(result.stderr)
	if missing {
		if info, err := os.Stat(archive); err == nil && info.Mode().IsRegular() {
			log.print("Skipped files that disappeared while archiving %s", source)
			return true, nil
		}
	}

	var startError *os.PathError
	missingParent := errors.As(result.err, &startError) && startError.Op == "chdir" && errors.Is(startError, fs.ErrNotExist)
	if missing || missingParent {
		if _, err := os.Lstat(source); errors.Is(err, fs.ErrNotExist) {
			log.print("Skipping vanished backup source %s", source)
			return false, nil
		}
	}
	return false, fmt.Errorf("unable to archive %s: %w", source, result.failure("7z"))
}

func newArchiveStage(parent, prefix, leaf string) (temp string, stage string, err error) {
	if parent != "" {
		if err := os.MkdirAll(parent, 0700); err != nil {
			return "", "", err
		}
	}

	temp, err = os.MkdirTemp(parent, prefix)
	if err != nil {
		return "", "", err
	}
	stage = filepath.Join(temp, leaf)
	if err := os.Mkdir(stage, 0700); err != nil {
		_ = os.RemoveAll(temp)
		return "", "", err
	}
	return temp, stage, nil
}

func readLiveDirectory(path string, log *runLogger) ([]os.DirEntry, error) {
	entries, err := os.ReadDir(path)
	if errors.Is(err, fs.ErrNotExist) {
		log.print("Skipping vanished backup directory %s", path)
		return nil, nil
	}
	return entries, err
}

func isOfficeLock(path string) bool { return strings.HasPrefix(filepath.Base(path), "~$") }

func stageGroups(ctx context.Context, source, password, parent string, status *runStatus, log *runLogger) (temp, stage string, err error) {
	temp, stage, err = newArchiveStage(parent, "backup-groups-", "groups")
	if err != nil {
		return "", "", err
	}
	defer func(path string) {
		if err != nil {
			_ = os.RemoveAll(path)
		}
	}(temp)

	entries, err := readLiveDirectory(source, log)
	if err != nil {
		return "", "", err
	}

	count := 0
	for _, entry := range entries {
		category := entry.Name()
		if isOfficeLock(category) || category == trashDirectory {
			continue
		}
		from := filepath.Join(source, category)
		to := filepath.Join(stage, category)
		if (category != "data" && category != "archive") || !entry.IsDir() {
			log.print("Preserving additional groups source entry %s", category)
			if err := copyEntry(ctx, from, to, isOfficeLock, "", log); err != nil {
				return "", "", err
			}
			continue
		}

		n, err := stageGroupCategory(ctx, from, to, category, password, status, log)
		if err != nil {
			return "", "", err
		}
		count += n
	}

	log.print("Created %d non-solid group archive(s)", count)
	return temp, stage, nil
}

func stageGroupCategory(ctx context.Context, from, to, category, password string, status *runStatus, log *runLogger) (int, error) {
	members, err := readLiveDirectory(from, log)
	if err != nil {
		return 0, err
	}
	if err := os.Mkdir(to, 0755); err != nil {
		return 0, err
	}

	count := 0
	for _, member := range members {
		name := member.Name()
		if isOfficeLock(name) {
			continue
		}
		if name == trashDirectory {
			log.print("Excluding retained trash from backup source %s", category)
			continue
		}

		source := filepath.Join(from, name)
		target := filepath.Join(to, name)
		if !member.IsDir() {
			log.print("Preserving non-group entry %s/%s", category, name)
			if err := copyEntry(ctx, source, target, isOfficeLock, "", log); err != nil {
				return 0, err
			}
			continue
		}

		relative := category + "/" + name
		log.print("Creating non-solid archive for %s", relative)
		status.write(map[string]any{"state": "running", "currentSource": relative, "message": "Archiving group " + relative, "activeFiles": []fileProgress{}})
		if _, err := os.Lstat(target + ".7z"); !errors.Is(err, fs.ErrNotExist) {
			return 0, fmt.Errorf("backup group archive conflicts with an existing entry: %s", relative)
		}
		created, err := makeArchive(ctx, source, target+".7z", password, log)
		if err != nil {
			return 0, err
		}
		if created {
			count++
		}
	}
	return count, nil
}

func stageEncrypted(ctx context.Context, sources []Source, options Options, status *runStatus, log *runLogger) (temp string, staged []Source, err error) {
	if options.Password == "" {
		return "", nil, errors.New("BACKUP_ARCHIVE_PASSWORD must be set when encryption is enabled")
	}

	temp, stage, err := newArchiveStage(options.ArchiveTemp, "backup-encrypted-", "encrypted")
	if err != nil {
		return "", nil, err
	}
	defer func(path string) {
		if err != nil {
			_ = os.RemoveAll(path)
		}
	}(temp)

	format := options.KeyFormat
	if format == "" {
		format = "7z-aes256"
	}
	metadata := struct {
		Format    string   `json:"format"`
		KeyID     string   `json:"keyId"`
		Encrypted bool     `json:"encrypted"`
		Archives  []string `json:"archives"`
	}{Format: format, KeyID: options.KeyID, Encrypted: true, Archives: []string{}}
	for _, source := range sources {
		name := strings.ReplaceAll(source.Destination, "/", "-") + ".7z"
		status.write(map[string]any{"state": "running", "currentSource": source.Destination, "message": "Encrypting " + source.Destination, "activeFiles": []fileProgress{}})
		created, err := makeArchive(ctx, source.Path, filepath.Join(stage, name), options.Password, log)
		if err != nil {
			return "", nil, err
		}
		if created {
			metadata.Archives = append(metadata.Archives, name)
		}
	}

	data, err := json.Marshal(metadata)
	if err != nil {
		return "", nil, err
	}
	if err := os.WriteFile(filepath.Join(stage, "backup-format.json"), data, 0600); err != nil {
		return "", nil, err
	}
	return temp, []Source{{stage, "encrypted"}}, nil
}
