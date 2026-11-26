package documents

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Only call from the disposable extraction helper. Keep this thread locked
// until exit: Landlock applies to the calling thread and its descendants, so
// input reads, result writes and third-party command launches stay on it.
func extractionSandbox(workspace string, timeout int) error {
	runtime.LockOSThread()

	for resource, maximum := range map[int]uint64{
		unix.RLIMIT_CORE: 0, unix.RLIMIT_AS: 2 << 30,
		unix.RLIMIT_FSIZE: 512 << 20, unix.RLIMIT_CPU: uint64(timeout),
	} {
		if err := unix.Setrlimit(resource, &unix.Rlimit{Cur: maximum, Max: maximum}); err != nil {
			return err
		}
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	if err := restrictExtractionFiles(workspace); err != nil {
		return fmt.Errorf("document Landlock isolation: %w", err)
	}
	if err := restrictExtractionNetwork(); err != nil {
		return fmt.Errorf("document network isolation: %w", err)
	}
	return nil
}

func restrictExtractionFiles(workspace string) error {
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		return errno
	}
	if abi < 1 {
		return errors.New("unsupported Landlock ABI")
	}
	handled := uint64((1 << 13) - 1)
	if abi >= 2 {
		handled |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		handled |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&handled)), unsafe.Sizeof(handled), 0)
	if errno != 0 {
		return errno
	}
	defer unix.Close(int(fd))

	const read = unix.LANDLOCK_ACCESS_FS_READ_FILE
	const readTree = read | unix.LANDLOCK_ACCESS_FS_READ_DIR | unix.LANDLOCK_ACCESS_FS_EXECUTE
	paths := []struct {
		path   string
		access uint64
	}{
		{workspace, handled &^ unix.LANDLOCK_ACCESS_FS_EXECUTE},
		{"/usr", readTree}, {"/lib", readTree}, {"/lib64", readTree}, {"/bin", readTree},
		{"/etc/fonts", readTree}, {"/etc/ghostscript", readTree},
		{"/etc/ld.so.cache", read}, {"/etc/papersize", read},
		{"/dev/null", read | unix.LANDLOCK_ACCESS_FS_WRITE_FILE}, {"/dev/urandom", read},
		{"/proc/cpuinfo", read}, {"/proc/meminfo", read},
	}
	for _, path := range paths {
		parent, err := unix.Open(path.path, unix.O_PATH|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOENT) && path.path != workspace {
			continue
		}
		if err != nil {
			return err
		}
		// Go's final padding does not affect the offsets of the two fields
		// in the kernel's packed landlock_path_beneath_attr.
		attr := struct {
			access uint64
			parent int32
		}{path.access, int32(parent)}
		_, _, errno = unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, fd, unix.LANDLOCK_RULE_PATH_BENEATH,
			uintptr(unsafe.Pointer(&attr)), 0, 0, 0)
		unix.Close(parent)
		if errno != 0 {
			return fmt.Errorf("%s: %w", path.path, errno)
		}
	}
	_, _, errno = unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func restrictExtractionNetwork() error {
	var arch uint32
	switch runtime.GOARCH {
	case "amd64":
		arch = unix.AUDIT_ARCH_X86_64
	case "arm64":
		arch = unix.AUDIT_ARCH_AARCH64
	default:
		return errors.New("unsupported document sandbox architecture")
	}
	const load = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
	const equal = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
	const ret = unix.BPF_RET | unix.BPF_K
	const deny = unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	filter := []unix.SockFilter{
		{Code: load, K: 4}, // seccomp_data.arch
		{Code: equal, Jt: 1, K: arch},
		{Code: ret, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: load, K: 0}, // seccomp_data.nr
	}
	if runtime.GOARCH == "amd64" {
		filter = append(filter, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, Jf: 1, K: 1 << 30},
			unix.SockFilter{Code: ret, K: deny})
	}
	// Keep parser descendants in the process group that the worker terminates
	// on completion, cancellation or timeout.
	for _, call := range []uint32{
		unix.SYS_SOCKET, unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER,
		unix.SYS_SETSID, unix.SYS_SETPGID,
	} {
		filter = append(filter, unix.SockFilter{Code: equal, Jf: 1, K: call}, unix.SockFilter{Code: ret, K: deny})
	}
	filter = append(filter, unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_ALLOW})
	program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	failedThread, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC,
		uintptr(unsafe.Pointer(&program)))
	runtime.KeepAlive(filter)
	if errno != 0 {
		return errno
	}
	if failedThread != 0 {
		return errors.New("could not synchronize document sandbox threads")
	}
	return nil
}
