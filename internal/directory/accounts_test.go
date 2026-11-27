package directory

import (
	"context"
	"errors"
	"strings"
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
	for _, invalid := range []string{"", `OTHER\user`, `EXAMPLE\`, "@example.test", "alice@", "a@b@c", "bad/entry", "bad\x00name"} {
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

func TestAgentUPNResolvesOnlyTheNamedADAccount(t *testing.T) {
	client := Client{Getenv: func(key string) string {
		return map[string]string{"REALM": "EXAMPLE.TEST", "WORKGROUP": "EXAMPLE"}[key]
	}}
	entry := func(sam, upn, sid, status string) Entry {
		return ParseLDIF("dn: CN=Fixture,DC=example,DC=test\nsAMAccountName: " + sam + "\nuserPrincipalName: " + upn +
			"\nobjectSid: " + sid + "\nuserAccountControl: " + status)[0]
	}
	const aliceSID = "S-1-5-21-1-2-3-1001"
	const aliasSID = "S-1-5-21-1-2-3-1002"
	responses := map[string][]Entry{
		"sAMAccountName=alice":                   {entry("Alice", "", aliceSID, "512")},
		"userPrincipalName=Ally@people.example":  {entry("Alice", "ally@PEOPLE.EXAMPLE", aliceSID, "512")},
		"userPrincipalName=alice@example.test":   {entry("Different", "alice@example.test", aliasSID, "512")},
		"userPrincipalName=alice@disabled.test":  {entry("Disabled", "alice@disabled.test", aliasSID, "514")},
		"userPrincipalName=alice@ambiguous.test": {entry("A", "alice@ambiguous.test", aliceSID, "512"), entry("B", "alice@ambiguous.test", aliasSID, "512")},
		"userPrincipalName=alice@excluded.test":  {entry("MSOL_hidden", "alice@excluded.test", aliasSID, "512")},
		"userPrincipalName=alice@mismatch.test":  {entry("Alice", "unrelated@example.test", aliceSID, "512")},
	}
	search := func(_ context.Context, filter string, _ []string) ([]Entry, error) {
		for selector, entries := range responses {
			if strings.Contains(filter, "("+selector+")") {
				return entries, nil
			}
		}
		return nil, nil
	}

	for name, want := range map[string]string{
		"alice": aliceSID, `EXAMPLE\alice`: aliceSID, "alice@EXAMPLE.TEST": aliceSID,
		"Ally@people.example": aliceSID, "alice@example.test": aliasSID,
		"alice@unknown.test": "", "alice@disabled.test": "", "alice@ambiguous.test": "",
		"alice@excluded.test": "", "alice@mismatch.test": "",
	} {
		t.Run(name, func(t *testing.T) {
			login, err := client.AccountLogin(name)
			if err != nil {
				t.Fatal(err)
			}
			sid, err := client.resolveLogin(t.Context(), login, search, time.Now())
			if sid != want || (want == "" && !errors.Is(err, ErrAccount)) || (want != "" && err != nil) {
				t.Fatalf("SID=%q error=%v, want %q", sid, err, want)
			}
		})
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
