// domainshare-backup is an optional offline restore and one-shot backup tool.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"unsafe"

	"github.com/stuck-lehnert/domainshare/internal/backup"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "[backup] %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 1 && args[0] == "run" {
		return backup.Run(ctx, backup.OptionsFromEnv(os.LookupEnv))
	}
	if len(args) == 0 || args[0] != "restore" {
		return errors.New("usage: domainshare-backup run | domainshare-backup restore [--legacy] ARCHIVE NEW_DIRECTORY")
	}
	flags := flag.NewFlagSet("restore", flag.ContinueOnError)
	legacy := flags.Bool("legacy", false, "prompt for the original archive password instead of the recovery phrase")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 2 {
		return errors.New("usage: domainshare-backup restore [--legacy] ARCHIVE NEW_DIRECTORY")
	}
	prompt := "24-word recovery phrase: "
	if *legacy {
		prompt = "Legacy archive password: "
	}
	secret, err := readSecret(ctx, prompt)
	if err != nil {
		return err
	}
	if !*legacy {
		secret, err = backup.ArchiveKey(secret)
		if err != nil {
			return err
		}
	}
	if err := backup.Restore(ctx, flags.Arg(0), flags.Arg(1), secret); err != nil {
		return err
	}
	fmt.Printf("Recovered into %s; inspect before copying to live storage.\n", flags.Arg(1))
	return nil
}

func readSecret(ctx context.Context, prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errors.New("recovery requires a terminal for hidden credential input")
	}
	defer tty.Close()

	var original syscall.Termios
	if err := changeTerminal(tty, syscall.TCGETS, &original); err != nil {
		return "", err
	}
	hidden := original
	hidden.Lflag &^= syscall.ECHO | syscall.ECHONL
	if err := changeTerminal(tty, syscall.TCSETS, &hidden); err != nil {
		return "", err
	}
	defer func() {
		_ = changeTerminal(tty, syscall.TCSETS, &original)
		_, _ = io.WriteString(tty, "\n")
	}()
	if _, err := io.WriteString(tty, prompt); err != nil {
		return "", err
	}

	type result struct {
		value string
		err   error
	}
	read := make(chan result, 1)
	go func() {
		value, err := bufio.NewReader(tty).ReadString('\n')
		read <- result{value: strings.TrimSuffix(value, "\n"), err: err}
	}()
	select {
	case r := <-read:
		return r.value, r.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func changeTerminal(tty *os.File, command uintptr, state *syscall.Termios) error {
	_, _, code := syscall.Syscall(syscall.SYS_IOCTL, tty.Fd(), command, uintptr(unsafe.Pointer(state)))
	if code != 0 {
		return code
	}
	return nil
}
