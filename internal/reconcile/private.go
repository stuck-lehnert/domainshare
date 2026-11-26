package reconcile

import (
	"context"
	"errors"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/stuck-lehnert/domainshare/internal/directory"
	"golang.org/x/sys/unix"
)

type PrivateDirectory interface {
	PrivateAccounts(context.Context) ([]directory.PrivateAccount, error)
}

type PrivateOptions struct {
	Root       string
	AdminGID   int
	Directory  PrivateDirectory
	IDs        func(context.Context, string) (name string, uid, gid int, err error)
	SkipUsers  string
	SkipPrefix string
	Logf       func(string, ...any)
}

func (options PrivateOptions) skip(sam string) bool {
	name := strings.ToLower(strings.TrimSpace(sam))
	if name == "" || name == "." || name == ".." || strings.ContainsAny(sam, "/\\\x00") || strings.HasSuffix(name, "$") || directory.IsExcludedUser(name) {
		return true
	}
	for _, r := range sam {
		if r < ' ' || r == 127 {
			return true
		}
	}
	reserved := []string{"administrator", "guest", "gast", "defaultaccount", "wdagutilityaccount", "fileshare_serviceacc", "fileshare_serviceaccount"}
	if slices.Contains(reserved, name) {
		return true
	}
	for user := range strings.SplitSeq(options.SkipUsers, ",") {
		if strings.EqualFold(strings.TrimSpace(user), name) {
			return true
		}
	}
	prefixes := append([]string{"fileshare_service", "aad_"}, strings.Split(options.SkipPrefix, ",")...)
	for _, prefix := range prefixes {
		if prefix = strings.ToLower(strings.TrimSpace(prefix)); prefix != "" && strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func SyncPrivate(ctx context.Context, options PrivateOptions) error {
	if options.Directory == nil || options.IDs == nil {
		return errors.New("private reconciliation requires live AD and winbind")
	}
	accounts, err := options.Directory.PrivateAccounts(ctx)
	if err != nil {
		return err
	}
	root, err := openShareRoot(options.Root)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := privateShareRoot(int(root.Fd())); err != nil {
		return err
	}

	names := make(map[string]string, len(accounts))
	for _, account := range accounts {
		key := strings.ToLower(account.SAM)
		if previous, exists := names[key]; exists && previous != account.SID {
			return errors.New("ambiguous AD account names; private ownership unchanged")
		}
		names[key] = account.SID
	}

	var failures int
	for _, account := range accounts {
		if err := ctx.Err(); err != nil {
			return err
		}
		if options.skip(account.SAM) {
			continue
		}
		name, uid, gid, err := options.IDs(ctx, account.SID)
		if err != nil || uid <= 0 || gid <= 0 || !strings.EqualFold(name, account.SAM) || options.skip(name) {
			if options.Logf != nil {
				options.Logf("Unable to resolve uid/gid for SID %s; skipping Private folder", account.SID)
			}
			continue
		}
		if err := syncPrivateAccount(ctx, root, name, uid, gid, options.AdminGID); err != nil {
			failures++
			if options.Logf != nil {
				options.Logf("Could not sync Private ACL for SID %s: %v", account.SID, err)
			}
		}
	}
	if failures != 0 {
		return errors.New("one or more Private folders could not be reconciled")
	}
	return ctx.Err()
}

func syncPrivateAccount(ctx context.Context, root *os.File, name string, uid, gid, admin int) error {
	err := unix.Mkdirat(int(root.Fd()), name, 0o700)
	created := err == nil
	if !created && !errors.Is(err, unix.EEXIST) {
		return err
	}
	folder, _, err := openChild(root, name, true)
	if err != nil {
		return err
	}
	defer folder.Close()
	var info unix.Stat_t
	if err := unix.Fstat(int(folder.Fd()), &info); err != nil {
		return err
	}
	if !created && info.Uid != uint32(uid) {
		// An AD account can be deleted and its name reused. An existing
		// directory must not be handed to a different mapped owner in that case.
		return errors.New("existing Private folder belongs to another UID")
	}

	return walkPrivate(ctx, folder, uid, gid, admin, true, 0)
}

func walkPrivate(ctx context.Context, file *os.File, uid, gid, admin int, isDir bool, depth int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if depth > 128 {
		return errors.New("Private tree exceeds the supported directory depth")
	}
	if err := privateACL(int(file.Fd()), uid, gid, admin, isDir); err != nil || !isDir {
		return err
	}

	for {
		names, err := file.Readdirnames(128)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		for _, name := range names {
			child, childDir, err := openChild(file, name, false)
			if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EXDEV) || errors.Is(err, errors.ErrUnsupported) {
				continue
			}
			if err != nil {
				return err
			}
			err = walkPrivate(ctx, child, uid, gid, admin, childDir, depth+1)
			child.Close()
			if err != nil {
				return err
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
	}
}

func SyncFSLogix(path string, groupGID, adminGID int) error {
	if groupGID <= 0 {
		return errors.New("FSLogix group GID unavailable; ACLs unchanged")
	}
	root, err := openShareRoot(path)
	if err != nil {
		return err
	}
	defer root.Close()
	return fslogixACL(int(root.Fd()), groupGID, adminGID)
}
