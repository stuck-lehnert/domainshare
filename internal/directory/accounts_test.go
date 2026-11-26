package directory

import (
	"errors"
	"testing"
	"time"
)

func TestAgentLoginMustNameALocalAccount(t *testing.T) {
	client := Client{Getenv: func(name string) string {
		if name == "WORKGROUP" {
			return "EXAMPLE"
		}
		return ""
	}}
	for _, invalid := range []string{"", `OTHER\user`, `EXAMPLE\`, "name@example.test", "bad/entry", "bad\x00name"} {
		if _, err := client.AccountLogin(invalid); err == nil {
			t.Errorf("accepted invalid account name %q", invalid)
		}
	}
	if username, err := client.AccountLogin(` example\Alice `); err != nil || username != "Alice" {
		t.Fatalf("qualified name: %q, %v", username, err)
	}
	if escaped := EscapeFilter(`(a*b)\`); escaped != `\28a\2ab\29\5c` {
		t.Fatalf("LDAP filter escaping: %q", escaped)
	}
}

func TestLiveAgentAccountStatus(t *testing.T) {
	const fixture = `Got 1 replies
dn: CN=Alice,DC=example,DC=test
sAMAccountName: Alice
objectSid:: AQEAAAAA
 AAUpAAAA
userAccountControl: 512
accountExpires: 0
`
	now := time.Date(2026, 11, 26, 18, 0, 0, 0, time.UTC)
	if sid, err := enabledAccount(ParseLDIF(fixture), "alice", now); err != nil || sid != "S-1-5-41" {
		t.Fatalf("binary SID in folded LDIF: %q, %v", sid, err)
	}
	for _, change := range []struct{ attr, value string }{
		{"useraccountcontrol", "514"}, {"useraccountcontrol", "528"}, {"accountExpires", "1"},
		{"lockoutTime", "1"}, {"msDS-User-Account-Control-Computed", "16"},
		{"sAMAccountName", "bob"}, {"objectSid", "garbage"},
	} {
		entries := ParseLDIF(fixture)
		entries[0][fold(change.attr)] = []Value{{Text: change.value}}
		if _, err := enabledAccount(entries, "Alice", now); !errors.Is(err, ErrAccount) {
			t.Errorf("accepted invalid live account attribute %s", change.attr)
		}
	}
}
