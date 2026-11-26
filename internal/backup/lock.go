package backup

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

var ErrBusy = errors.New("another backup process is already running")

// AcquireLock holds the lock shared with Python workers and settings writes.
// Closing the returned file releases the lock.
func AcquireLock(stateRoot string) (*os.File, error) {
	if stateRoot == "" {
		return nil, errors.New("STATE_ROOT is required for the backup lock")
	}

	lock, err := os.OpenFile(LockPath(stateRoot), os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, err
	}

	info, err := lock.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = errors.New("backup lock is not a regular file")
	}
	if err == nil {
		err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	}
	if err != nil {
		_ = lock.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrBusy
		}
		return nil, err
	}
	return lock, nil
}
