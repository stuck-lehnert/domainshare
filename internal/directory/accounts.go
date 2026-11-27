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
	"unicode"
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

// AccountLogin validates an AD sign-in name without guessing the account
// behind a UPN. An alternate UPN's prefix need not be its sAMAccountName.
func (client Client) AccountLogin(username string) (string, error) {
	name := strings.TrimSpace(username)
	if !utf8.ValidString(username) || utf8.RuneCountInString(username) > 256 || name == "" {
		return "", errors.New("Benutzername ist erforderlich")
	}
	if strings.IndexFunc(username, unicode.IsControl) >= 0 || strings.Contains(name, "/") {
		return "", errors.New("Ungültiger Benutzername")
	}
	if domain, account, ok := strings.Cut(name, "\\"); ok {
		if domain == "" || (!strings.EqualFold(domain, client.env("WORKGROUP")) && !strings.EqualFold(domain, client.env("REALM"))) {
			return "", errors.New("Benutzername gehört nicht zur konfigurierten Domäne")
		}
		if account != "" && !strings.ContainsAny(account, `\@`) {
			return account, nil
		}
		return "", errors.New("Ungültiger Benutzername")
	}

	if local, suffix, ok := strings.Cut(name, "@"); ok {
		if local == "" || suffix == "" || strings.Contains(suffix, "@") || strings.IndexFunc(suffix, unicode.IsSpace) >= 0 {
			return "", errors.New("Ungültiger Benutzername")
		}
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
	name, err := client.AccountLogin(username)
	if err != nil {
		return "", err
	}
	return client.resolveLogin(ctx, name, client.Search, time.Now())
}

func (client Client) resolveLogin(ctx context.Context, name string, search func(context.Context, string, []string) ([]Entry, error), now time.Time) (string, error) {
	lookup := func(attribute, value string) ([]Entry, error) {
		filter := "(&(objectClass=user)(!(objectClass=computer))(" + attribute + "=" + EscapeFilter(value) + "))"
		return search(ctx, filter, []string{
			"distinguishedName", "sAMAccountName", "userPrincipalName", "objectSid", "userAccountControl", "accountExpires",
			"msDS-User-Account-Control-Computed", "lockoutTime",
		})
	}

	sam := name
	if local, suffix, upn := strings.Cut(name, "@"); upn {
		entries, err := lookup("userPrincipalName", name)
		if err != nil {
			return "", err
		}
		if len(entries) > 0 {
			if len(entries) != 1 || !strings.EqualFold(entries[0].First("userPrincipalName"), name) {
				return "", ErrAccount
			}
			return enabledAccount(entries, entries[0].First("sAMAccountName"), now)
		}

		// Implicit UPNs use sAMAccountName and the actual AD DNS realm.
		// An unknown alternate suffix must never resolve to a bare account.
		if !strings.EqualFold(suffix, client.env("REALM")) {
			return "", ErrAccount
		}
		sam = local
	}

	if IsExcludedUser(sam) || strings.HasSuffix(sam, "$") {
		return "", ErrAccount
	}
	entries, err := lookup("sAMAccountName", sam)
	if err != nil {
		return "", err
	}
	return enabledAccount(entries, sam, now)
}

func enabledAccount(entries []Entry, sam string, now time.Time) (string, error) {
	if len(entries) != 1 || sam == "" || IsExcludedUser(sam) || strings.HasSuffix(sam, "$") {
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
