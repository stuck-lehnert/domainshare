package reconcile

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPrivateACLMatchesSetfacl(t *testing.T) {
	setfacl, err := exec.LookPath("setfacl")
	if err != nil {
		t.Skip("setfacl not installed")
	}
	getfacl, err := exec.LookPath("getfacl")
	if err != nil {
		t.Skip("getfacl not installed")
	}
	root := t.TempDir()
	uid, gid := os.Getuid(), os.Getgid()
	admin := gid + 1
	for _, isDir := range []bool{true, false} {
		t.Run(fmt.Sprintf("directory=%t", isDir), func(t *testing.T) {
			rights := "rw-"
			if isDir {
				rights = "rwx"
			}
			path, reference := filepath.Join(root, "go"+rights), filepath.Join(root, "oracle"+rights)
			for _, p := range []string{path, reference} {
				if isDir {
					err = os.Mkdir(p, 0o700)
				} else {
					err = os.WriteFile(p, nil, 0o600)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			fd, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer fd.Close()
			if err := privateACL(int(fd.Fd()), uid, gid, admin, isDir); err != nil {
				t.Fatal(err)
			}

			entries := fmt.Sprintf("u::%s,u:%d:%s,g::---,g:%d:%s,m::%s,o::---", rights, uid, rights, admin, rights, rights)
			if output, err := exec.Command(setfacl, "-m", entries, reference).CombinedOutput(); err != nil {
				t.Fatalf("setfacl: %s (%v)", output, err)
			}
			if isDir {
				if output, err := exec.Command(setfacl, "-d", "-m", entries, reference).CombinedOutput(); err != nil {
					t.Fatalf("setfacl default: %s (%v)", output, err)
				}
			}
			acl := func(path string) string {
				output, err := exec.Command(getfacl, "-c", "-n", path).CombinedOutput()
				if err != nil {
					t.Fatalf("getfacl: %s (%v)", output, err)
				}
				return strings.TrimSpace(string(output))
			}
			want, got := acl(reference), acl(path)
			if got != want {
				t.Fatalf("ACL mismatch\nexpected:\n%s\nactual:\n%s", want, got)
			}
		})
	}
}

func TestOpenChildRejectsLinksAndSpecialFiles(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "other.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(root, "hardlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "symlink")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(root, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := openShareRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()

	for _, name := range []string{"hardlink", "symlink", "fifo"} {
		file, _, err := openChild(fd, name, false)
		if file != nil {
			_ = file.Close()
		}
		if !errors.Is(err, errors.ErrUnsupported) && !errors.Is(err, unix.ELOOP) {
			t.Errorf("openChild %s: %v", name, err)
		}
	}
}
