package config

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

var publicFields = func() map[string]field {
	result := make(map[string]field, len(schema.Fields))
	for _, item := range schema.Fields {
		result[item.Key] = item
	}
	return result
}()

var (
	dnsName   = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$`)
	netbios   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,15}$`)
	groupSID  = regexp.MustCompile(`^S-[0-9]+(?:-[0-9]+)+$`)
	languages = regexp.MustCompile(`^[a-z]{3}(?:\+[a-z]{3})*$`)
	digits    = regexp.MustCompile(`^[0-9]+$`)
)

// Validate normalizes a public setting and never includes its value in errors.
func Validate(name string, value any) (any, error) {
	spec, ok := publicFields[name]
	if !ok {
		return nil, fmt.Errorf("unbekannte Einstellung")
	}
	invalid := func(message string) (any, error) {
		return nil, fmt.Errorf("%s: %s", spec.Label, message)
	}

	switch spec.Kind {
	case "bool":
		switch value := value.(type) {
		case bool:
			return value, nil
		case string:
			if value == "true" || value == "1" {
				return true, nil
			}
			if value == "false" || value == "0" {
				return false, nil
			}
		case json.Number:
			if number, err := value.Float64(); err == nil && (number == 1 || number == 0) {
				return number == 1, nil
			}
		case int:
			if value == 0 || value == 1 {
				return value == 1, nil
			}
		}
		return invalid("ungültiger Schalter")
	case "int":
		text, err := envValue(value)
		if err != nil || !digits.MatchString(text) {
			return invalid("ganze Zahl erforderlich")
		}
		number, err := strconv.Atoi(text)
		if err != nil || number < spec.Minimum || number > spec.Maximum {
			return invalid("Wert außerhalb des zulässigen Bereichs")
		}
		return json.Number(strconv.Itoa(number)), nil
	}

	text, ok := value.(string)
	pem := strings.Contains(spec.Kind, "pem")
	maximum := 4096
	if pem {
		maximum = 65536
	}
	if !ok || !utf8.ValidString(text) || utf8.RuneCountInString(text) > maximum {
		return invalid("ungültiger Wert")
	}
	if strings.ContainsRune(text, 0) || (!pem && strings.ContainsAny(text, "\r\n")) {
		return invalid("ungültige Steuerzeichen")
	}
	if spec.Kind != "secret" && spec.Kind != "secretpem" {
		text = strings.TrimSpace(text)
	}
	if text == "" {
		return text, nil
	}

	switch spec.Kind {
	case "dns":
		if len(text) > 253 || !dnsName.MatchString(text) {
			return invalid("ungültiger DNS-Name")
		}
	case "netbios":
		if !netbios.MatchString(text) {
			return invalid("höchstens 15 Buchstaben/Ziffern, _ oder -")
		}
	case "group":
		if !groupSID.MatchString(text) {
			return invalid("ungültige Gruppen-SID")
		}
	case "ip":
		if _, err := netip.ParseAddr(text); err != nil {
			return invalid("ungültige IP-Adresse")
		}
	case "languages":
		if !languages.MatchString(text) {
			return invalid("ungültige OCR-Sprachen")
		}
	case "choice":
		if !slices.Contains(spec.Choices, text) {
			return invalid("ungültige Auswahl")
		}
	case "pem":
		if (name == "ACME_CA_CERTIFICATES_PEM" || name == "TLS_CA_ROOT_PEM") &&
			!x509.NewCertPool().AppendCertsFromPEM([]byte(text)) {
			return invalid("ungültiges PEM-Zertifikat")
		}
	case "https", "ldap", "secreturl":
		if !validURL(text, spec.Kind) {
			return invalid("ungültige Adresse")
		}
	case "origins":
		for item := range strings.SplitSeq(text, ",") {
			origin := strings.TrimSpace(item)
			if !validURL(origin, "https") || strings.ContainsAny(origin, "?#") ||
				strings.IndexFunc(origin, unicode.IsSpace) >= 0 {
				return invalid("ungültiger HTTPS-Origin")
			}
			parsed, _ := url.Parse(origin)
			if parsed.Path != "" || strings.HasSuffix(parsed.Host, ":") {
				return invalid("ungültiger HTTPS-Origin")
			}
		}
	}
	return text, nil
}

func validURL(text, kind string) bool {
	parsed, err := url.Parse(text)
	if err != nil || parsed.Hostname() == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}

	switch kind {
	case "https":
		if parsed.Scheme != "https" || parsed.User != nil {
			return false
		}
	case "ldap":
		if parsed.Scheme != "ldap" && parsed.Scheme != "ldaps" {
			return false
		}
	case "secreturl":
		switch parsed.Scheme {
		case "rsync", "sftp", "smb", "cifs", "davfs", "dav", "webdav", "https", "http":
		default:
			return false
		}
	}
	if port := parsed.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return false
		}
	}

	decoded, err := url.PathUnescape(text)
	return err == nil && !strings.ContainsAny(decoded, "\r\n\x00")
}
