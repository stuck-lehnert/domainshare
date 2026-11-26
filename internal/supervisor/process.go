package supervisor

import (
	"errors"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type process struct {
	command *exec.Cmd
	done    chan struct{}
	mu      sync.Mutex
	err     error
}

func start(environment []string, argv []string) (*process, error) {
	command := exec.Command(argv[0], argv[1:]...)
	command.Env = environment
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return nil, err
	}

	child := &process{command: command, done: make(chan struct{})}
	go func() {
		// Keep the leader waitable until the group has been cleaned up. This
		// prevents PID reuse while signaling descendants left by a dead leader.
		for {
			var info unix.Siginfo
			err := unix.Waitid(unix.P_PID, command.Process.Pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil {
				child.err = command.Wait()
				close(child.done)
				return
			}
			break
		}

		child.mu.Lock()
		_ = unix.Kill(-command.Process.Pid, unix.SIGKILL)
		child.err = command.Wait()
		close(child.done)
		child.mu.Unlock()
	}()
	return child, nil
}

func (child *process) exited() bool {
	if child == nil {
		return false
	}
	select {
	case <-child.done:
		return true
	default:
		return false
	}
}

func (child *process) exitCode() int {
	if child.err == nil {
		return 0
	}
	var failure *exec.ExitError
	if errors.As(child.err, &failure) {
		return failure.ExitCode()
	}
	return -1
}

func (child *process) stop() {
	if child == nil || child.exited() {
		return
	}

	child.signalGroup(syscall.SIGTERM)
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()

	select {
	case <-child.done:
	case <-deadline.C:
		child.signalGroup(syscall.SIGKILL)
		<-child.done
	}
}

func (child *process) signalGroup(signal syscall.Signal) {
	child.mu.Lock()
	if !child.exited() {
		_ = syscall.Kill(-child.command.Process.Pid, signal)
	}
	child.mu.Unlock()
}
