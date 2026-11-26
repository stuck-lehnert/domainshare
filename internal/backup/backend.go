package backup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type destination struct {
	scheme, host, user, password, redacted string
	basePath, path, namespace              string
	port                                   int
}

var namespacePattern = regexp.MustCompile(`^(keys/[a-f0-9]{24}|plain)$`)

func parseDestination(raw, namespace string) (destination, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Hostname() == "" || u.Opaque != "" {
		// url.Error includes the original URL, potentially with credentials.
		return destination{}, errors.New("BACKUP_DESTINATION must be a valid URL with a scheme and hostname")
	}
	var d destination
	d.scheme = strings.ToLower(u.Scheme)
	d.host = strings.ToLower(u.Hostname())
	d.basePath, d.path = u.Path, u.Path
	if value := u.Port(); value != "" {
		d.port, err = strconv.Atoi(value)
		if err != nil || d.port < 1 || d.port > 65535 {
			return destination{}, errors.New("invalid backup destination port")
		}
	}
	if u.User != nil {
		d.user = u.User.Username()
		d.password, _ = u.User.Password()
	}
	if strings.ContainsAny(d.user+d.password+d.path+d.host, "\r\n\x00") {
		return destination{}, errors.New("backup destination contains unsupported characters")
	}
	for _, part := range strings.Split(d.path, "/") {
		if part == "." || part == ".." {
			return destination{}, errors.New("backup destination path contains a traversal component")
		}
	}
	if strings.Trim(d.path, "/") == "" {
		switch d.scheme {
		case "rsync":
			return destination{}, errors.New("rsync destinations must include a module path")
		case "smb", "cifs":
			return destination{}, errors.New("smb destinations must include a share name")
		}
	}
	namespace = strings.Trim(namespace, "/")
	if namespace != "" {
		if !namespacePattern.MatchString(namespace) {
			return destination{}, errors.New("invalid backup key namespace")
		}
		d.namespace = namespace
		d.path = strings.TrimRight(d.basePath, "/") + "/" + namespace
	}
	d.redacted = d.scheme + "://" + d.hostPort() + u.EscapedPath()
	if d.user != "" {
		identity := url.User(d.user).String()
		if _, hasPassword := u.User.Password(); hasPassword {
			identity += ":***"
		}
		d.redacted = d.scheme + "://" + identity + "@" + d.hostPort() + u.EscapedPath()
	}
	return d, nil
}

func (d destination) hostPort() string {
	host := d.host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if d.port != 0 {
		host += ":" + strconv.Itoa(d.port)
	}
	return host
}

func joinRemote(parts ...string) string {
	var path []string
	for _, part := range parts {
		if part = strings.Trim(part, "/"); part != "" {
			path = append(path, part)
		}
	}
	return strings.Join(path, "/")
}

type commandResult struct {
	stdout, stderr string
	err            error
}

func (r commandResult) code() int {
	var exit *exec.ExitError
	if errors.As(r.err, &exit) {
		return exit.ExitCode()
	}
	return -1
}

func (r commandResult) failure(name string) error {
	if r.err == nil {
		return nil
	}
	output := strings.TrimSpace(r.stderr)
	if output == "" {
		output = strings.TrimSpace(r.stdout)
	}
	if len(output) > 16000 {
		output = output[len(output)-16000:]
	}
	if output != "" {
		return fmt.Errorf("command failed (%s): %w: %s", name, r.err, output)
	}
	return fmt.Errorf("command failed (%s): %w", name, r.err)
}

func runCaptured(cmd *exec.Cmd) commandResult {
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	return commandResult{stdout: out.String(), stderr: stderr.String(), err: err}
}

type backend interface {
	close()
	directories(ctx context.Context) ([]string, error)
	hasMarker(ctx context.Context, snapshot string) (bool, error)
	writeMarker(ctx context.Context, snapshot string) error
	deleteSnapshot(ctx context.Context, snapshot string) error
	syncSource(ctx context.Context, snapshot string, source Source, progress *transferProgress) error
}

var rcloneSchemes = map[string]string{
	"sftp": "sftp", "smb": "smb", "cifs": "smb",
	"davfs": "webdav", "dav": "webdav", "webdav": "webdav", "http": "webdav", "https": "webdav",
}

func openBackend(ctx context.Context, d destination) (backend, error) {
	if d.scheme == "rsync" {
		modulePath := joinRemote(d.path)
		if modulePath == "" {
			return nil, errors.New("rsync destinations must include a module path")
		}
		if strings.ContainsAny(d.user, "@/:\\") {
			return nil, errors.New("invalid rsync destination username")
		}
		user := ""
		if d.user != "" {
			user = d.user + "@"
		}
		env := append(os.Environ(), "LC_ALL=C")
		if d.password != "" {
			env = append(env, "RSYNC_PASSWORD="+d.password)
		}
		return &rsyncBackend{base: "rsync://" + user + d.hostPort() + "/" + modulePath, env: env}, nil
	}
	return openRclone(ctx, d)
}

type rcloneBackend struct {
	prefix string
	config string
}

func openRclone(ctx context.Context, d destination) (*rcloneBackend, error) {
	typ, ok := rcloneSchemes[d.scheme]
	if !ok {
		return nil, fmt.Errorf("unsupported BACKUP_DESTINATION scheme %q (supported: rsync, sftp, smb, cifs, davfs, dav, webdav, http, https)", d.scheme)
	}
	values := map[string]string{"type": typ}
	if d.user != "" {
		values["user"] = d.user
	}
	prefix := ""
	switch typ {
	case "smb", "sftp":
		values["host"] = d.host
		if d.port != 0 {
			values["port"] = strconv.Itoa(d.port)
		}
		prefix = joinRemote(d.path)
		if typ == "smb" {
			if prefix == "" {
				return nil, errors.New("smb destinations must include a share name")
			}
			if separator := strings.IndexAny(d.user, ";\\"); separator >= 0 {
				values["domain"] = d.user[:separator]
				values["user"] = d.user[separator+1:]
			}
			// Rclone's SMB root is the SMB server; the share is the first
			// path segment of backup:share/prefix, not a config setting.
		}
	case "webdav":
		scheme := d.scheme
		if scheme != "http" && scheme != "https" {
			scheme = "https"
		}
		// Keep the configured WebDAV endpoint at the existing base. A new
		// key namespace is a relative path that rclone can create.
		path := d.basePath
		if path == "" {
			path = "/"
		}
		values["url"] = (&url.URL{Scheme: scheme, Host: d.hostPort(), Path: path}).String()
		values["vendor"] = "other"
		prefix = d.namespace
	}

	if d.password != "" {
		cmd := exec.CommandContext(ctx, "rclone", "obscure", "-")
		cmd.Stdin = strings.NewReader(d.password + "\n")
		result := runCaptured(cmd)
		pass := strings.TrimSpace(result.stdout)
		if result.err != nil || pass == "" || strings.ContainsAny(pass, "\r\n\x00") {
			return nil, errors.New("could not prepare rclone credentials")
		}
		values["pass"] = pass
	}

	file, err := os.CreateTemp("", "backup-rclone-*.conf")
	if err != nil {
		return nil, err
	}
	var config strings.Builder
	config.WriteString("[backup]\n")
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(&config, "%s = %s\n", key, values[key])
	}
	_, writeErr := io.WriteString(file, config.String())
	if err := errors.Join(writeErr, file.Close()); err != nil {
		_ = os.Remove(file.Name())
		return nil, err
	}
	return &rcloneBackend{prefix: prefix, config: file.Name()}, nil
}

func (b *rcloneBackend) close() { _ = os.Remove(b.config) }

func (b *rcloneBackend) remote(parts ...string) string {
	return "backup:" + joinRemote(b.prefix, "snapshots", joinRemote(parts...))
}

func (b *rcloneBackend) command(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, "rclone", append(args, "--config", b.config)...)
}

func (b *rcloneBackend) directories(ctx context.Context) ([]string, error) {
	result := runCaptured(b.command(ctx, "lsf", b.remote(), "--dirs-only", "--format", "p"))
	if result.code() == 3 {
		return nil, nil // destination/snapshots has not yet been created
	}
	if result.err != nil {
		return nil, result.failure("rclone")
	}
	return snapshotNames(strings.Split(result.stdout, "\n")), nil
}

func (b *rcloneBackend) hasMarker(ctx context.Context, snapshot string) (bool, error) {
	result := runCaptured(b.command(ctx, "lsf", b.remote(snapshot), "--files-only", "--include", ".backup_complete"))
	if result.err != nil {
		return false, result.failure("rclone")
	}
	for _, line := range strings.Split(result.stdout, "\n") {
		if strings.TrimSpace(line) == ".backup_complete" {
			return true, nil
		}
	}
	return false, nil
}

func (b *rcloneBackend) writeMarker(ctx context.Context, snapshot string) error {
	cmd := b.command(ctx, "rcat", b.remote(snapshot, ".backup_complete"))
	cmd.Stdin = strings.NewReader(timestamp(time.Now()) + "\n")
	return runCaptured(cmd).failure("rclone")
}

func (b *rcloneBackend) deleteSnapshot(ctx context.Context, snapshot string) error {
	if !validSnapshot(snapshot) {
		return errors.New("invalid backup snapshot name; refusing deletion")
	}
	return runCaptured(b.command(ctx, "purge", b.remote(snapshot))).failure("rclone")
}

func (b *rcloneBackend) syncSource(ctx context.Context, snapshot string, source Source, progress *transferProgress) error {
	seconds := strconv.FormatInt(max(1, int64(progress.interval/time.Second)), 10)
	args := []string{"sync", source.Path + "/", b.remote(snapshot, source.Destination),
		"--create-empty-src-dirs", "--progress", "--stats", seconds + "s", "--transfers", "12", "--log-level", "INFO", "--exclude", officeLockPattern}
	if excludesRootTrash(source.Destination) {
		args = append(args, "--exclude", "/"+trashDirectory+"/**")
	}
	result := runTransfer(b.command(ctx, args...), progress)
	if result.err != nil && ctx.Err() == nil && progress.vanished {
		progress.log.print("A source file disappeared while syncing %s; retrying the source", source.Destination)
		progress.resetAttempt()
		result = runTransfer(b.command(ctx, args...), progress)
	}
	return result.failure("rclone")
}

type rsyncBackend struct {
	base string
	env  []string
}

func (*rsyncBackend) close() {}

func (b *rsyncBackend) remote(parts ...string) string {
	return b.base + "/" + joinRemote("snapshots", joinRemote(parts...))
}

func (b *rsyncBackend) command(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "rsync", args...)
	cmd.Env = b.env
	return cmd
}

func rsyncListing(output string, mode byte) []string {
	var matches []string
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 5 && fields[0][0] == mode {
			matches = append(matches, fields[4])
		}
	}
	return matches
}

var missingRsyncDirectory = regexp.MustCompile(`\b(chdir|change_dir|link_stat)\b[^\r\n]*No such file or directory \(2\)`)

func (b *rsyncBackend) directories(ctx context.Context) ([]string, error) {
	result := runCaptured(b.command(ctx, "--list-only", b.remote()+"/"))
	if result.err != nil {
		if missingRsyncDirectory.MatchString(result.stderr + "\n" + result.stdout) {
			return nil, nil
		}
		return nil, result.failure("rsync")
	}
	return snapshotNames(rsyncListing(result.stdout, 'd')), nil
}

func (b *rsyncBackend) hasMarker(ctx context.Context, snapshot string) (bool, error) {
	result := runCaptured(b.command(ctx, "--list-only", b.remote(snapshot)+"/"))
	if result.err != nil {
		return false, result.failure("rsync")
	}
	for _, file := range rsyncListing(result.stdout, '-') {
		if file == ".backup_complete" {
			return true, nil
		}
	}
	return false, nil
}

func (b *rsyncBackend) writeMarker(ctx context.Context, snapshot string) error {
	marker, err := os.CreateTemp("", "backup-marker-")
	if err != nil {
		return err
	}
	defer os.Remove(marker.Name())
	_, writeErr := io.WriteString(marker, timestamp(time.Now())+"\n")
	if err := errors.Join(writeErr, marker.Close()); err != nil {
		return err
	}
	return runCaptured(b.command(ctx, "-a", "--mkpath", marker.Name(), b.remote(snapshot, ".backup_complete"))).failure("rsync")
}

func (b *rsyncBackend) deleteSnapshot(ctx context.Context, snapshot string) error {
	if !validSnapshot(snapshot) {
		return errors.New("invalid backup snapshot name; refusing deletion")
	}
	empty, err := os.MkdirTemp("", "backup-empty-")
	if err != nil {
		return err
	}
	defer os.Remove(empty)
	return runCaptured(b.command(ctx, "-a", "--delete", "--include", "/"+snapshot+"/***", "--exclude", "*", empty+"/", b.remote()+"/")).failure("rsync")
}

func (b *rsyncBackend) syncSource(ctx context.Context, snapshot string, source Source, progress *transferProgress) error {
	args := []string{"-a", "--delete", "--mkpath", "--progress", "--outbuf=L"}
	if excludesRootTrash(source.Destination) {
		args = append(args, "--exclude=/"+trashDirectory+"/")
	}
	args = append(args, "--exclude="+officeLockPattern, source.Path+"/", b.remote(snapshot, source.Destination)+"/")
	result := runTransfer(b.command(ctx, args...), progress)
	if result.code() == 24 {
		progress.log.print("Skipping rsync source files that disappeared during the backup (exit 24)")
		return nil
	}
	return result.failure("rsync")
}
