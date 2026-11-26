// Package directory resolves Active Directory accounts using Samba and Kerberos.
package directory

import (
	"context"
	"errors"
	"math"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/cases"
)

var ErrAccount = errors.New("AD account is unavailable")

type Identity struct {
	Username string `json:"sub"`
	SID      string `json:"sid"`
	UID      *int   `json:"uid"`
	Role     string `json:"role"`
}

func (id Identity) Admin() bool { return id.Role == "domain-admin" }

type Environment func(string) string

type Client struct {
	Getenv Environment
}

func (client Client) env(name string) string {
	if client.Getenv != nil {
		return client.Getenv(name)
	}
	return os.Getenv(name)
}

func fold(value string) string { return cases.Fold().String(value) }

func IsExcludedUser(user string) bool {
	name := strings.TrimSpace(user)
	if last := strings.LastIndexByte(name, '\\'); last >= 0 {
		name = name[last+1:]
	}
	name, _, _ = strings.Cut(name, "@")
	name = fold(name)
	return name == "krbtgt" || strings.HasPrefix(name, "msol_")
}

// AccountLogin accepts a mandatory sAMAccountName or configured DOMAIN\user.
func (client Client) AccountLogin(username string) (string, error) {
	name := strings.TrimSpace(username)
	if !utf8.ValidString(username) || utf8.RuneCountInString(username) > 256 || name == "" {
		return "", errors.New("Benutzername ist erforderlich")
	}
	if domain, account, ok := strings.Cut(name, "\\"); ok {
		if fold(domain) != fold(client.env("WORKGROUP")) || domain == "" {
			return "", errors.New("Benutzername gehört nicht zur konfigurierten Domäne")
		}
		name = account
	}

	if name == "" || strings.ContainsAny(name, `\/@`) || strings.IndexFunc(name, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
		return "", errors.New("Ungültiger Benutzername")
	}
	return name, nil
}

const (
	accountDisabled = 0x02
	accountLocked   = 0x10
)

// ResolveAccount performs a live lookup, not a winbind name-cache lookup.
// It returns ErrAccount for absent, disabled, locked and expired users.
func (client Client) ResolveAccount(ctx context.Context, username string) (string, error) {
	sam, err := client.AccountLogin(username)
	if err != nil {
		return "", err
	}
	if IsExcludedUser(sam) || strings.HasSuffix(sam, "$") {
		return "", ErrAccount
	}
	filter := "(&(objectClass=user)(!(objectClass=computer))(sAMAccountName=" + EscapeFilter(sam) + "))"
	entries, err := client.Search(ctx, filter, []string{
		"distinguishedName", "sAMAccountName", "objectSid", "userAccountControl", "accountExpires",
		"msDS-User-Account-Control-Computed", "lockoutTime",
	})
	if err != nil {
		return "", err
	}
	return enabledAccount(entries, sam, time.Now())
}

func enabledAccount(entries []Entry, sam string, now time.Time) (string, error) {
	if len(entries) != 1 {
		return "", ErrAccount
	}
	entry := entries[0]
	if (entry.First("distinguishedName") == "" && entry.First("dn") == "") || fold(entry.First("sAMAccountName")) != fold(sam) {
		return "", ErrAccount
	}
	sid := entry.SID()
	if !strings.HasPrefix(sid, "S-1-") {
		return "", ErrAccount
	}

	flags, err := strconv.ParseInt(entry.First("userAccountControl"), 10, 64)
	if err != nil || flags < 0 || flags&(accountDisabled|accountLocked) != 0 {
		return "", ErrAccount
	}
	computed := entry.First("msDS-User-Account-Control-Computed")
	if computed != "" {
		value, err := strconv.ParseInt(computed, 10, 64)
		if err != nil || value < 0 || value&accountLocked != 0 {
			return "", ErrAccount
		}
	} else if lockout := entry.First("lockoutTime"); lockout != "" {
		if value, err := strconv.ParseInt(lockout, 10, 64); err != nil || value > 0 {
			return "", ErrAccount
		}
	}

	if raw := entry.First("accountExpires"); raw != "" {
		expires, err := strconv.ParseInt(raw, 10, 64)
		filetime := (now.Unix()+11644473600)*10_000_000 + int64(now.Nanosecond()/100)
		if err != nil || (expires != 0 && expires != math.MaxInt64 && expires <= filetime) {
			return "", ErrAccount
		}
	}
	return sid, nil
}

var anySID = regexp.MustCompile(`(?i)S-[0-9]+(?:-[0-9]+)+`)

func (client Client) CurrentIdentity(ctx context.Context, sid string) (Identity, error) {
	if !sidText.MatchString(sid) {
		return Identity{}, ErrAccount
	}
	groups, err := run(ctx, 15*time.Second, "wbinfo", "--user-sids", sid)
	if err != nil {
		return Identity{}, err
	}
	resolved, err := run(ctx, 15*time.Second, "wbinfo", "--sid-to-name", sid)
	if err != nil {
		return Identity{}, err
	}
	username, userType := strings.CutSuffix(strings.TrimSpace(string(resolved)), " 1")
	if !userType || username == "" || IsExcludedUser(username) {
		return Identity{}, ErrAccount
	}
	mapped, err := run(ctx, 15*time.Second, "wbinfo", "--sid-to-uid", sid)
	if err != nil {
		return Identity{}, err
	}
	uid, err := strconv.Atoi(strings.TrimSpace(string(mapped)))
	if err != nil || uid < 0 {
		return Identity{}, ErrAccount
	}

	role := "user"
	for _, groupSID := range anySID.FindAllString(string(groups), -1) {
		if strings.EqualFold(groupSID, client.env("DOMAIN_ADMINS_SID")) {
			role = "domain-admin"
			break
		}
	}
	return Identity{Username: username, SID: sid, UID: &uid, Role: role}, nil
}

func run(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	deadline, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return exec.CommandContext(deadline, name, args...).Output()
}
