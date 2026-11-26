package documents

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type watchPath struct {
	source, relative string
}

type indexEvent struct {
	watchPath
	rescan bool
}

type indexWatcher struct {
	fd    int
	paths map[int]watchPath
	buf   []byte
}

func newIndexWatcher() (*indexWatcher, error) {
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		return nil, err
	}
	return &indexWatcher{fd: fd, paths: make(map[int]watchPath), buf: make([]byte, 64<<10)}, nil
}

func (watcher *indexWatcher) add(dir *os.File, path watchPath) {
	const mask = unix.IN_ATTRIB | unix.IN_CLOSE_WRITE | unix.IN_MOVED_FROM | unix.IN_MOVED_TO |
		unix.IN_CREATE | unix.IN_DELETE | unix.IN_DELETE_SELF | unix.IN_MOVE_SELF | unix.IN_ONLYDIR
	// Resolve through the descriptor of a validated directory, not an
	// untrusted path that can be replaced with a symlink between operations.
	wd, err := unix.InotifyAddWatch(watcher.fd, fmt.Sprintf("/proc/self/fd/%d", dir.Fd()), mask)
	if err == nil {
		watcher.paths[wd] = path
	}
}

func (watcher *indexWatcher) events() ([]indexEvent, error) {
	var result []indexEvent
	_, err := unix.Poll([]unix.PollFd{{Fd: int32(watcher.fd), Events: unix.POLLIN}}, 500)
	if errors.Is(err, unix.EINTR) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	n, err := unix.Read(watcher.fd, watcher.buf)
	if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	for offset := 0; offset+unix.SizeofInotifyEvent <= n; {
		data := watcher.buf[offset:]
		wd := int(int32(binary.NativeEndian.Uint32(data[:4])))
		mask := binary.NativeEndian.Uint32(data[4:8])
		length := int(binary.NativeEndian.Uint32(data[12:16]))
		offset += unix.SizeofInotifyEvent + length
		if offset > n {
			return nil, errors.New("truncated document inotify event")
		}
		if mask&unix.IN_Q_OVERFLOW != 0 {
			return []indexEvent{{rescan: true}}, nil
		}
		path, known := watcher.paths[wd]
		if !known {
			continue
		}
		if mask&unix.IN_IGNORED != 0 {
			delete(watcher.paths, wd)
		}
		name, _, _ := strings.Cut(string(data[unix.SizeofInotifyEvent:unix.SizeofInotifyEvent+length]), "\x00")
		if name == ".trash" {
			continue
		}
		if path.source == "" || name == "" || mask&(unix.IN_ISDIR|unix.IN_DELETE_SELF|unix.IN_MOVE_SELF|unix.IN_IGNORED) != 0 {
			result = append(result, indexEvent{watchPath: path, rescan: true})
		} else {
			path.relative = appendPath(path.relative, name)
			result = append(result, indexEvent{watchPath: path})
		}
	}
	return result, nil
}

func openDirectoryChild(dir *os.File, name string, rootStat stat) (*os.File, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, directoryFlags, 0)
	if err != nil {
		return nil, classifyPathError(err)
	}
	info, err := fdStat(fd)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	if !sameMount(info, rootStat) {
		unix.Close(fd)
		return nil, os.ErrNotExist
	}
	return os.NewFile(uintptr(fd), name), nil
}

func (index indexer) watch(ctx context.Context) {
	watcher, err := newIndexWatcher()
	if err != nil {
		index.log("File events unavailable; using periodic scans: %v", err)
	} else {
		defer unix.Close(watcher.fd)
	}
	var nextSources, nextScan, heartbeat time.Time
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if now := time.Now(); now.Sub(heartbeat) > time.Second {
			if _, err := index.db.ExecContext(ctx, `UPDATE document_worker SET heartbeat=? WHERE id=1`, unixTime()); err != nil {
				return err
			}
			heartbeat = now
		}
		return index.cancelled(ctx)
	}
	var sources map[string]indexSource
	for ctx.Err() == nil {
		if err := check(); err != nil {
			if errors.Is(err, errIndexPaused) {
				nextSources, nextScan = time.Time{}, time.Time{}
				_, _ = index.db.ExecContext(ctx, `UPDATE document_worker SET scanning=0 WHERE id=1 AND scanning<>0`)
				waitIndex(ctx, 500*time.Millisecond)
			} else {
				waitIndex(ctx, time.Second)
			}
			continue
		}

		now := time.Now()
		full := !now.Before(nextScan)
		rescan := make(map[string]bool)
		if full || !now.Before(nextSources) {
			updated, changed, err := index.refreshSources(ctx)
			if err != nil {
				if !errors.Is(err, errIndexPaused) && ctx.Err() == nil {
					index.log("Catalog refresh failed: %v", err)
				}
				waitIndex(ctx, time.Second)
				continue
			}
			sources = updated
			nextSources = now.Add(2 * time.Second)
			for _, id := range changed {
				rescan[id] = true
			}
			if watcher != nil {
				for _, path := range []string{index.DataRoot, index.PrivateRoot} {
					if dir, _, err := openDirectory(path, nil, nil); err == nil {
						watcher.add(dir, watchPath{})
						dir.Close()
					}
				}
			}
		}
		if full {
			for id := range sources {
				rescan[id] = true
			}
			nextScan = now.Add(time.Duration(indexSetting("DOCUMENT_SCAN_SECONDS", 30, 2, 3600)) * time.Second)
		}

		changed := make(map[watchPath]bool)
		if watcher != nil {
			events, err := watcher.events()
			if err != nil {
				index.log("File event read failed: %v", err)
				watcher = nil // File descriptor is closed by defer.
				nextScan = time.Time{}
			}
			for _, event := range events {
				switch {
				case !event.rescan:
					changed[event.watchPath] = true
				case event.source != "":
					rescan[event.source] = true
				default:
					nextSources, nextScan = time.Time{}, time.Time{}
				}
			}
		}

		for id := range rescan {
			source, exists := sources[id]
			if !exists || check() != nil {
				continue
			}
			if _, err := index.db.ExecContext(ctx, `UPDATE document_worker SET scanning=1 WHERE id=1`); err != nil {
				continue
			}
			err := index.scanSource(ctx, source, watcher, check)
			_, _ = index.db.ExecContext(ctx, `UPDATE document_worker SET scanning=0,last_scan=CASE WHEN ? THEN ? ELSE last_scan END WHERE id=1`,
				err == nil, unixTime())
			if err != nil && !errors.Is(err, errIndexPaused) && !errors.Is(err, os.ErrNotExist) && ctx.Err() == nil {
				index.log("Catalog scan failed for %s: %v", id, err)
			}
		}
		for event := range changed {
			source, exists := sources[event.source]
			if !exists || rescan[event.source] || check() != nil {
				continue
			}
			if err := discoverFile(ctx, index.db, source, event.relative, 0); err != nil && ctx.Err() == nil {
				index.log("Catalog file event failed for %s: %v", event.source, err)
			}
		}
		if watcher == nil {
			waitIndex(ctx, 500*time.Millisecond)
		}
	}
}
