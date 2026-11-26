package sambaacl

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidatePinnedWriterInputs(t *testing.T) {
	root := t.TempDir()
	regular := scratchFile(t, root, "file")
	database := scratchFile(t, root, "fixture.tdb")
	directory, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	fileACL, err := NewDescriptor(nil, testAdmin, Options{})
	if err != nil {
		t.Fatal(err)
	}
	dirACL, err := NewDescriptor(nil, testAdmin, Options{Directory: true})
	if err != nil {
		t.Fatal(err)
	}
	writer := Writer{HelperPath: self, Database: database}

	for name, options := range map[string]struct {
		writer Writer
		file   *os.File
		acl    Descriptor
	}{
		"missing target": {writer, nil, fileACL},
		"wrong kind":     {writer, directory, fileACL},
		"aliased DB":     {writer, database, fileACL},
		"directory DB":   {Writer{HelperPath: self, Database: directory}, regular, fileACL},
		"relative helper": {
			Writer{HelperPath: "domainshare-sambaacl", Database: database}, regular, fileACL,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := options.writer.prepare(t.Context(), options.file, options.acl); err == nil {
				t.Fatal("accepted invalid writer inputs")
			}
		})
	}

	prepared, err := writer.prepare(t.Context(), directory, dirACL)
	if err != nil || prepared.mode != 0o777 || prepared.kind != "directory" {
		t.Fatalf("directory preparation: %+v, %v", prepared, err)
	}
	prepared, err = writer.prepare(t.Context(), regular, fileACL)
	if err != nil || prepared.mode != 0o666 || prepared.kind != "file" {
		t.Fatalf("file preparation: %+v, %v", prepared, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := writer.SetACLFD(ctx, regular, fileACL); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled ACL request: %v", err)
	}
}

func scratchFile(t *testing.T, root, name string) *os.File {
	t.Helper()
	file, err := os.OpenFile(filepath.Join(root, name), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { file.Close() })
	return file
}

// Run explicitly with the compiled Bookworm helper. Files are always created
// in t.TempDir; the test accepts no path to an existing database.
func TestBookwormPinnedInodeStorage(t *testing.T) {
	helper := os.Getenv("DOMAINSHARE_ACL_TEST_HELPER")
	if helper == "" {
		t.Skip("set DOMAINSHARE_ACL_TEST_HELPER to run Samba integration")
	}
	root := t.TempDir()
	target := scratchFile(t, root, "original")
	database := scratchFile(t, root, "fixture.tdb")
	writer := Writer{HelperPath: helper, Database: database}
	descriptor, err := NewDescriptor(map[string]int{"S-1-5-21-1-2-3-1000": 3}, testAdmin, Options{})
	if err != nil {
		t.Fatal(err)
	}
	write, err := writer.prepare(t.Context(), target, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.store(target, write); err != nil {
		t.Fatalf("initialize new scratch TDB: %v", err)
	}

	// A Fedora Python verifier can independently read Bookworm's TDB output;
	// it must not load the extracted Bookworm shared libraries in that process.
	python := func(code string, args ...string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "python3", append([]string{"-c", code}, args...)...)
		for _, variable := range os.Environ() {
			if !strings.HasPrefix(variable, "LD_LIBRARY_PATH=") {
				cmd.Env = append(cmd.Env, variable)
			}
		}
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("Samba fixture verifier: %v\n%s", err, output)
		}
	}
	python(`
from samba import xattr_tdb
import sys
xattr_tdb.wrap_setxattr(sys.argv[1], sys.argv[2], 'user.fixture', b'preserved')
`, database.Name(), target.Name())

	renamed := filepath.Join(root, "renamed")
	if err := os.Rename(target.Name(), renamed); err != nil {
		t.Fatal(err)
	}
	decoy := scratchFile(t, root, "original")
	newACL, err := NewDescriptor(nil, testAdmin, Options{})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := writer.prepare(t.Context(), target, newACL)
	if err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if err := writer.SetACLFD(t.Context(), target, newACL); err != nil {
			t.Fatal(err)
		}
		info, err := target.Stat()
		if err != nil || info.Mode().Perm() != 0o666 {
			t.Fatalf("local mode not applied after storing ACL: %v, %v", info, err)
		}
	} else if err := writer.store(target, updated); err != nil {
		t.Fatal(err)
	}

	python(`
from samba import xattr_tdb
import errno, sys
db, renamed, decoy, blob = sys.argv[1:]
assert xattr_tdb.wrap_getxattr(db, renamed, 'security.NTACL') == bytes.fromhex(blob)
assert xattr_tdb.wrap_getxattr(db, renamed, 'user.fixture') == b'preserved'
try:
    xattr_tdb.wrap_getxattr(db, decoy, 'security.NTACL')
except (TypeError, RuntimeError, OSError) as error:
    assert error.args[0] in (errno.EINVAL, errno.ENODATA), error
else:
    raise AssertionError('replacement inode was updated')
`, database.Name(), renamed, decoy.Name(), hex.EncodeToString(updated.blob))

	readOnlyDB, err := os.Open(database.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer readOnlyDB.Close()
	readOnlyWriter := Writer{HelperPath: helper, Database: readOnlyDB}
	if err := readOnlyWriter.store(target, write); err == nil || !strings.Contains(err.Error(), "opened read-write") {
		t.Fatalf("helper did not reject a read-only database FD: %v", err)
	}
}
