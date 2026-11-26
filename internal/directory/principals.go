package directory

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var (
	domainSID = regexp.MustCompile(`^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$`)
	guidText  = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

const matchInChain = "1.2.840.113556.1.4.1941"

var principalAttributes = []string{
	"objectGUID", "objectSid", "distinguishedName", "sAMAccountName", "displayName",
	"name", "cn", "objectClass", "member", "memberOf", "primaryGroupID",
}

type Principal struct {
	GUID, SID, SAM, Name, DN string
	PrimaryRID               int
	Members, MemberOf        []string
	Class                    string
}

type Group struct {
	SID  string `json:"sid"`
	Name string `json:"name"`
}

func DomainSID(sid string) bool { return domainSID.MatchString(sid) }

func NormalizeDN(dn string) string { return fold(strings.TrimSpace(dn)) }

func (entry Entry) GUID() string {
	values := entry["objectguid"]
	if len(values) != 1 {
		return ""
	}
	value := values[0]
	if !value.Base64 {
		if guidText.MatchString(value.Text) {
			return strings.ToLower(value.Text)
		}
		return ""
	}

	guid, err := base64.StdEncoding.DecodeString(value.Text)
	if err != nil || len(guid) != 16 {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x", binary.LittleEndian.Uint32(guid),
		binary.LittleEndian.Uint16(guid[4:]), binary.LittleEndian.Uint16(guid[6:]), guid[8:10], guid[10:16])
}

func entryPrincipal(entry Entry) (Principal, bool) {
	dn := entry.First("distinguishedName")
	if dn == "" {
		dn = entry.First("dn")
	}
	if dn == "" {
		return Principal{}, false
	}

	classes := entry.Values("objectClass")
	for i, value := range classes {
		classes[i] = strings.ToLower(value)
	}
	var class string
	switch {
	case slices.Contains(classes, "group"):
		class = "group"
	case slices.Contains(classes, "user") && !slices.Contains(classes, "computer"):
		class = "user"
	default:
		return Principal{}, false
	}

	primaryRID, err := strconv.Atoi(entry.First("primaryGroupID"))
	if err != nil || primaryRID < 0 {
		primaryRID = -1
	}
	sid, sam := entry.SID(), entry.First("sAMAccountName")
	name := entry.First("displayName")
	if name == "" {
		name = cmp.Or(sam, sid)
	}
	return Principal{GUID: entry.GUID(), SID: sid, SAM: sam, Name: name, DN: dn, PrimaryRID: primaryRID,
		Members: entry.Values("member"), MemberOf: entry.Values("memberOf"), Class: class}, true
}

func (client Client) Principals(ctx context.Context, includeGroups bool) (users, groups map[string]Principal, err error) {
	filter := "(&(objectClass=user)(!(objectClass=computer)))"
	if includeGroups {
		filter = "(|" + filter + "(objectClass=group))"
	}
	entries, err := client.Search(ctx, filter, principalAttributes)
	if err != nil {
		return nil, nil, err
	}
	users, groups = make(map[string]Principal), make(map[string]Principal)
	for _, entry := range entries {
		principal, ok := entryPrincipal(entry)
		if !ok || !DomainSID(principal.SID) {
			continue
		}
		principal.DN = NormalizeDN(principal.DN)
		for i, dn := range principal.Members {
			principal.Members[i] = NormalizeDN(dn)
		}
		if principal.Class == "group" {
			groups[principal.DN] = principal
		} else {
			users[principal.SID] = principal
		}
	}
	return users, groups, nil
}

func (client Client) ListGroups(ctx context.Context) ([]Group, error) {
	entries, err := client.Search(ctx, "(objectClass=group)", []string{"distinguishedName", "objectSid", "objectClass", "sAMAccountName"})
	if err != nil {
		return nil, err
	}
	groups := make([]Group, 0, len(entries))
	for _, entry := range entries {
		principal, ok := entryPrincipal(entry)
		if ok && principal.Class == "group" && DomainSID(principal.SID) {
			groups = append(groups, Group{SID: principal.SID, Name: cmp.Or(principal.SAM, principal.SID)})
		}
	}
	slices.SortStableFunc(groups, func(a, b Group) int { return cmp.Compare(fold(a.Name), fold(b.Name)) })
	return groups, nil
}

func (client Client) CurrentIdentityWithAdminSID(ctx context.Context, sid, adminSID string) (Identity, error) {
	if !DomainSID(adminSID) {
		return Identity{}, ErrAccount
	}
	copy := Client{Getenv: func(key string) string {
		if key == "DOMAIN_ADMINS_SID" {
			return adminSID
		}
		return client.env(key)
	}}
	return copy.CurrentIdentity(ctx, sid)
}
