package directory

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"time"
)

type PrivateAccount struct {
	SID, SAM string
}

// PrivateAccounts enumerates login-capable AD accounts. A failed search never
// falls back to provisioning folders from an unverified name cache.
func (client Client) PrivateAccounts(ctx context.Context) ([]PrivateAccount, error) {
	const filter = "(&(objectClass=user)(!(objectClass=computer)))"
	entries, err := client.Search(ctx, filter, []string{
		"distinguishedName", "sAMAccountName", "objectSid", "userAccountControl", "accountExpires",
		"msDS-User-Account-Control-Computed", "lockoutTime",
	})
	if err != nil {
		return nil, err
	}

	now := time.Now()
	result := make([]PrivateAccount, 0, len(entries))
	for _, entry := range entries {
		name := entry.First("sAMAccountName")
		if name == "" || IsExcludedUser(name) || strings.HasSuffix(name, "$") {
			continue
		}
		sid, err := enabledAccount([]Entry{entry}, name, now)
		if err == nil && DomainSID(sid) {
			result = append(result, PrivateAccount{SID: sid, SAM: name})
		}
	}
	slices.SortFunc(result, func(a, b PrivateAccount) int { return strings.Compare(a.SAM, b.SAM) })
	return result, nil
}

func GroupID(ctx context.Context, sid string) (int, error) {
	if !DomainSID(sid) {
		return 0, ErrAccount
	}
	result, err := run(ctx, 15*time.Second, "wbinfo", "--sid-to-gid", sid)
	if err != nil {
		return 0, err
	}
	gid, err := positiveID(strings.TrimSpace(string(result)))
	return gid, err
}

func PrivateIDs(ctx context.Context, sid string) (name string, uid, gid int, err error) {
	if !DomainSID(sid) {
		return "", 0, 0, ErrAccount
	}
	result, err := run(ctx, 15*time.Second, "wbinfo", "--sid-to-uid", sid)
	if err != nil {
		return "", 0, 0, err
	}
	uid, err = positiveID(strings.TrimSpace(string(result)))
	if err != nil {
		return "", 0, 0, err
	}
	result, err = run(ctx, 15*time.Second, "getent", "passwd", strconv.Itoa(uid))
	if err != nil {
		return "", 0, 0, err
	}
	fields := strings.Split(strings.TrimSpace(string(result)), ":")
	if len(fields) != 7 || fields[2] != strconv.Itoa(uid) {
		return "", 0, 0, ErrAccount
	}
	name = fields[0]
	if _, account, qualified := strings.Cut(name, "\\"); qualified {
		name = account
	}
	gid, err = positiveID(fields[3])
	return name, uid, gid, err
}

func positiveID(value string) (int, error) {
	parsed, err := strconv.ParseUint(value, 10, 31)
	if err != nil || parsed == 0 {
		return 0, ErrAccount
	}
	return int(parsed), nil
}
