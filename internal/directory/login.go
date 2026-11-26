package directory

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var defaultPrincipal = regexp.MustCompile(`(?m)^Default principal:\s*([^\s@\\/]+)@([^\s]+)\s*$`)

func (client Client) Authenticate(ctx context.Context, username, password string) (Identity, error) {
	name := strings.TrimSpace(username)
	if name == "" || utf8.RuneCountInString(name) > 256 || strings.ContainsAny(name, "\r\n\x00") ||
		password == "" || utf8.RuneCountInString(password) > 4096 || strings.ContainsAny(password, "\r\n\x00") {
		return Identity{}, ErrAccount
	}

	workgroup, realm := client.env("WORKGROUP"), client.env("REALM")
	if workgroup == "" || realm == "" {
		return Identity{}, ErrAccount
	}
	account, principal, enterprise := name, "", false
	switch {
	case strings.Contains(name, "\\"):
		domain, local, _ := strings.Cut(name, "\\")
		if fold(domain) != fold(workgroup) {
			return Identity{}, ErrAccount
		}
		account = local
		principal = account + "@" + realm
	case strings.Contains(name, "@"):
		local, suffix, _ := strings.Cut(name, "@")
		if suffix == "" || strings.Contains(suffix, "@") || fold(suffix) == fold(workgroup) || strings.IndexFunc(suffix, unicode.IsSpace) >= 0 {
			return Identity{}, ErrAccount
		}
		account, principal, enterprise = local, name, true
	default:
		principal = account + "@" + realm
	}
	if account == "" || strings.ContainsAny(account, `@\/`) || IsExcludedUser(account) {
		return Identity{}, ErrAccount
	}

	cacheDir := client.env("WEB_AUTH_CACHE_DIR")
	if cacheDir == "" {
		cacheDir = "/tmp"
	}
	cache, err := os.CreateTemp(cacheDir, "web-auth-")
	if err != nil {
		return Identity{}, ErrAccount
	}
	defer os.Remove(cache.Name())
	if err := cache.Close(); err != nil {
		return Identity{}, ErrAccount
	}

	environment := append(os.Environ(), "KRB5CCNAME=FILE:"+cache.Name(), "LC_ALL=C")
	args := []string{"--", principal}
	if enterprise {
		args = append([]string{"-C", "-E"}, args...)
	}
	if _, err := kerberos(ctx, environment, password+"\n", "kinit", args...); err != nil {
		return Identity{}, ErrAccount
	}

	if enterprise {
		output, err := kerberos(ctx, environment, "", "klist", "-c", cache.Name())
		if err != nil {
			return Identity{}, ErrAccount
		}
		match := defaultPrincipal.FindSubmatch(output)
		if match == nil || fold(string(match[2])) != fold(realm) || IsExcludedUser(string(match[1])) {
			return Identity{}, ErrAccount
		}
		account = string(match[1])
	}
	if err := os.Remove(cache.Name()); err != nil && !os.IsNotExist(err) {
		return Identity{}, ErrAccount
	}

	result, err := run(ctx, 15*time.Second, "wbinfo", "--name-to-sid", workgroup+"\\"+account)
	if err != nil {
		return Identity{}, ErrAccount
	}
	userSID := anySID.Find(result)
	if userSID == nil {
		return Identity{}, ErrAccount
	}
	return client.CurrentIdentity(ctx, string(userSID))
}

func kerberos(ctx context.Context, environment []string, stdin, name string, args ...string) ([]byte, error) {
	deadline, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	command := exec.CommandContext(deadline, name, args...)
	command.Env = environment
	if stdin != "" {
		command.Stdin = strings.NewReader(stdin)
	}
	return command.Output()
}
