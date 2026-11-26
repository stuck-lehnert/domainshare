package backup

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Run stages, uploads, and applies retention to a single backup. An empty
// destination or another process holding the lock is a successful no-op.
func Run(ctx context.Context, options Options) error {
	if strings.TrimSpace(options.Destination) == "" {
		log := newLogger(options)
		defer log.close()
		log.print("BACKUP_DESTINATION is unset, skipping backup")
		return nil
	}
	err := RunConfigured(ctx, options.StateRoot, func() (Options, error) { return options, nil })
	if errors.Is(err, ErrBusy) {
		log := newLogger(options)
		defer log.close()
		log.print("Another backup process is already running; skipping this cycle")
		return nil
	}
	return err
}

// RunConfigured reads options while holding the same lock taken by settings
// writes. A pending worker cannot start with an outdated destination or key.
func RunConfigured(ctx context.Context, root string, load func() (Options, error)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if root == "" {
		return errors.New("STATE_ROOT is required for a backup")
	}
	if err := os.MkdirAll(root, 0755); err != nil {
		return err
	}
	lock, err := AcquireLock(root)
	if err != nil {
		return err
	}
	defer lock.Close()

	options, err := load()
	if err != nil {
		return err
	}
	if options.StateRoot != root {
		return errors.New("backup options do not match the locked state directory")
	}
	if strings.TrimSpace(options.Destination) == "" {
		return nil
	}
	return runLocked(ctx, options)
}

func runLocked(ctx context.Context, options Options) (err error) {
	log := newLogger(options)
	defer log.close()

	d, parseErr := parseDestination(strings.TrimSpace(options.Destination), options.Namespace)
	trigger := options.Trigger
	if trigger == "" {
		trigger = "manual"
	}
	status := newStatus(options.StatusPath, d.redacted, trigger, log)
	defer func() {
		if err != nil {
			message := redactError(err.Error(), options.Password, d.password)
			log.print("ERROR: %s", message)
			status.finish(false, message)
			if message != err.Error() {
				err = errors.New(message)
			}
		}
	}()
	if parseErr != nil {
		return parseErr
	}

	b, err := openBackend(ctx, d)
	if err != nil {
		return err
	}
	defer b.close()
	pendingPath := journalPath(options.StateRoot, d)
	if err := cleanupPending(ctx, b, pendingPath, log); err != nil {
		return err
	}

	sources, cleanup, err := stageSources(ctx, options, status, log)
	if err != nil {
		return err
	}
	defer cleanup()
	if len(sources) == 0 {
		message := "No backup sources are available, skipping backup"
		log.print("%s", message)
		status.finish(true, message)
		return nil
	}

	log.print("Starting backup to %s", d.redacted)
	existing, err := b.directories(ctx)
	if err != nil {
		return err
	}
	name, err := chooseSnapshotName(time.Now(), existing)
	if err != nil {
		return err
	}
	log.print("Creating snapshot %s", name)
	status.write(map[string]any{"snapshot": name, "message": "Measuring backup payload"})

	sizes, total, err := measurePayload(ctx, sources)
	if err != nil {
		return err
	}
	log.print("Backup payload size: %s", formatSize(total))
	status.write(map[string]any{"state": "running", "totalBytes": total, "message": "Backup payload: " + formatSize(total)})

	if err := writeAtomic(pendingPath, []byte(name+"\n"), true); err != nil {
		return err
	}
	if err := upload(ctx, b, name, options, sources, sizes, total, status, log); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if cleanupErr := cleanupPending(cleanupCtx, b, pendingPath, log); cleanupErr != nil {
			log.print("Could not clean up snapshot %s; will retry on the next backup: %s", name, redactError(cleanupErr.Error(), d.password))
		}
		return err
	}
	if err := os.Remove(pendingPath); err != nil {
		return err
	}

	retained, err := prune(ctx, b, options.Retention, log)
	if err != nil {
		return err
	}
	status.finish(true, fmt.Sprintf("Backup completed; %d snapshot(s) retained", retained))
	return nil
}

func redactError(message string, secrets ...string) string {
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		message = strings.ReplaceAll(message, secret, "***")
		message = strings.ReplaceAll(message, url.QueryEscape(secret), "***")
		message = strings.ReplaceAll(message, url.PathEscape(secret), "***")
	}
	return message
}

func stageSources(ctx context.Context, options Options, status *runStatus, log *runLogger) (sources []Source, cleanup func(), err error) {
	var tempDirs []string
	cleanupDirs := func() {
		for _, dir := range tempDirs {
			if err := os.RemoveAll(dir); err != nil {
				log.warn("could not clean staging directory: %v", err)
			}
		}
	}
	defer func() {
		if err != nil {
			cleanupDirs()
		}
	}()
	if options.Encrypted && options.Password == "" {
		return nil, nil, errors.New("BACKUP_ARCHIVE_PASSWORD must be set when encryption is enabled")
	}
	if err := validatePassword(options.Password); err != nil {
		return nil, nil, err
	}

	destinations := make(map[string]bool)
	for _, source := range options.Sources {
		name := source.Destination
		if !filepath.IsLocal(name) || name == "." || name != filepath.Clean(name) || strings.ContainsAny(name, "\\:\r\n\x00") {
			return nil, nil, errors.New("backup source must have a relative snapshot path")
		}
		if options.Encrypted {
			name = strings.ReplaceAll(name, "/", "-")
		}
		if destinations[name] {
			return nil, nil, fmt.Errorf("duplicate backup source destination: %s", name)
		}
		destinations[name] = true

		path, err := filepath.Abs(source.Path)
		if err != nil {
			return nil, nil, err
		}
		info, err := os.Stat(path)
		if errors.Is(err, fs.ErrNotExist) || (err == nil && !info.IsDir()) {
			log.print("Skipping missing source: %s", path)
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		source.Path = path
		var temp string
		switch {
		case source.Destination == "state":
			status.write(map[string]any{"message": "Creating consistent state database snapshot"})
			temp, source.Path, err = stageState(ctx, path, options, log)
		case source.Destination == "data/groups" && !options.Encrypted:
			status.write(map[string]any{"state": "running", "currentSource": "data/groups", "message": "Creating group archives"})
			password := options.Password
			if options.KeyID != "" {
				password = ""
			}
			temp, source.Path, err = stageGroups(ctx, path, password, options.ArchiveTemp, status, log)
		}
		if err != nil {
			return nil, nil, err
		}
		if temp != "" {
			tempDirs = append(tempDirs, temp)
		}
		sources = append(sources, source)
	}

	if options.Encrypted && len(sources) > 0 {
		temp, encrypted, err := stageEncrypted(ctx, sources, options, status, log)
		if err != nil {
			return nil, nil, err
		}
		tempDirs = append(tempDirs, temp)
		sources = encrypted
	}
	return sources, cleanupDirs, nil
}

func measurePayload(ctx context.Context, sources []Source) ([]int64, int64, error) {
	sizes := make([]int64, len(sources))
	var total int64
	for i, source := range sources {
		err := filepath.WalkDir(source.Path, func(path string, entry fs.DirEntry, err error) error {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			if err != nil {
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			rootTrash := entry.Name() == trashDirectory && excludesRootTrash(source.Destination) && filepath.Dir(path) == source.Path
			if path != source.Path && (isOfficeLock(path) || (rootTrash && entry.IsDir())) {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if !entry.Type().IsRegular() {
				return nil
			}
			info, err := entry.Info()
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			if err != nil {
				return err
			}
			sizes[i] += info.Size()
			return nil
		})
		if err != nil {
			return nil, 0, err
		}
		total += sizes[i]
	}
	return sizes, total, nil
}

func upload(ctx context.Context, b backend, name string, options Options, sources []Source, sizes []int64, total int64, status *runStatus, log *runLogger) error {
	interval := options.ProgressInterval
	if interval <= 0 {
		interval = 10 * time.Second
	}
	interactive := options.ProgressMode == "always"
	if options.ProgressMode != "never" && !interactive {
		if file, ok := log.stderr.(*os.File); ok {
			interactive = isTTY(file)
		}
	}
	var base int64
	for index, source := range sources {
		log.print("Syncing %s", source.Destination)
		progress := &transferProgress{source: source, sourceSize: sizes[index], base: base,
			total: total, interval: interval, log: log, status: status, interactive: interactive}
		progress.resetAttempt()
		progress.report(time.Now(), true)
		err := b.syncSource(ctx, name, source, progress)
		if err == nil {
			progress.maxTransferred = sizes[index]
			clear(progress.active)
		}
		progress.report(time.Now(), true)
		if interactive {
			fmt.Fprint(log.stderr, "\r\x1b[K")
		}
		if err != nil {
			return err
		}
		base += sizes[index]
	}
	return b.writeMarker(ctx, name)
}
