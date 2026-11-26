package directory

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"
)

// Search reads the local domain using Samba's machine trust first. The LDAP
// bind fallback uses the same configured URI and private password file as
// the reference backend. Filters must escape values before interpolation.
func (client Client) Search(ctx context.Context, filter string, attributes []string) ([]Entry, error) {
	const timeout = 120 * time.Second
	args := append([]string{"ads", "search", "-P", filter}, attributes...)
	if output, err := run(ctx, timeout, "net", args...); err == nil {
		return ParseLDIF(string(output)), nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	realm, username, password := client.env("REALM"), client.env("JOIN_USER"), client.env("JOIN_PASSWORD")
	if realm == "" || username == "" || password == "" {
		return nil, errors.New("AD lookup failed and LDAP fallback credentials are not configured")
	}
	uri := client.env("LDAP_URI")
	if uri == "" {
		uri = "ldaps://" + client.env("DOMAIN")
	}
	base := client.env("LDAP_BASE_DN")
	if base == "" {
		base = "DC=" + strings.ReplaceAll(realm, ".", ",DC=")
	}

	secret, err := os.CreateTemp("", "domainshare-ldap-")
	if err != nil {
		return nil, err
	}
	defer os.Remove(secret.Name())
	_, writeErr := secret.WriteString(password + "\n")
	if err := errors.Join(writeErr, secret.Close()); err != nil {
		return nil, err
	}

	args = append([]string{"-LLL", "-x", "-H", uri, "-D", username + "@" + realm,
		"-y", secret.Name(), "-b", base, filter}, attributes...)
	output, err := run(ctx, timeout, "ldapsearch", args...)
	if err != nil {
		return nil, errors.New("AD lookup failed")
	}
	return ParseLDIF(string(output)), nil
}
