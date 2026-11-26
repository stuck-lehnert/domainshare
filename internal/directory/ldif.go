package directory

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

var sidText = regexp.MustCompile(`(?i)^S-[0-9]+(?:-[0-9]+)+$`)

type Value struct {
	Text   string
	Base64 bool
}

type Entry map[string][]Value

// ParseLDIF accepts both the LDIF form and Samba's net ads search header.
func ParseLDIF(output string) []Entry {
	lines := strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n")
	unfolded := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.HasPrefix(line, " ") && len(unfolded) != 0 {
			unfolded[len(unfolded)-1] += line[1:]
		} else {
			unfolded = append(unfolded, line)
		}
	}

	entries := make([]Entry, 0)
	current := make(Entry)
	for _, line := range unfolded {
		line = strings.TrimSpace(line)
		if line == "" {
			if len(current) > 0 {
				entries = append(entries, current)
				current = make(Entry)
			}
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}

		name, value, ok := strings.Cut(line, ":")
		if !ok || name == "" {
			continue
		}
		name = strings.ToLower(name)
		value, encoded := strings.CutPrefix(value, ":")
		current[name] = append(current[name], Value{Text: strings.TrimSpace(value), Base64: encoded})
	}
	if len(current) > 0 {
		entries = append(entries, current)
	}
	return entries
}

func (value Value) string() string {
	if value.Base64 {
		if raw, err := base64.StdEncoding.DecodeString(value.Text); err == nil && utf8.Valid(raw) {
			return strings.TrimSpace(string(raw))
		}
	}
	return value.Text
}

func (entry Entry) First(name string) string {
	values := entry.Values(name)
	if len(values) > 0 {
		return values[0]
	}
	return ""
}

// Values includes attributes returned with LDAP options such as member;range=.
// It does not imply that AD returned every range for an oversized attribute.
func (entry Entry) Values(name string) []string {
	name = strings.ToLower(name)
	var options []string
	for key := range entry {
		if strings.HasPrefix(key, name+";") {
			options = append(options, key)
		}
	}
	slices.Sort(options)

	var values []string
	for _, key := range append([]string{name}, options...) {
		for _, raw := range entry[key] {
			if text := raw.string(); text != "" {
				values = append(values, text)
			}
		}
	}
	return values
}

func (entry Entry) SID() string {
	values := entry["objectsid"]
	if len(values) != 1 {
		return ""
	}
	value := values[0]
	if !value.Base64 {
		if sidText.MatchString(value.Text) {
			return strings.ToUpper(value.Text)
		}
		return ""
	}

	raw, err := base64.StdEncoding.DecodeString(value.Text)
	if err != nil || len(raw) < 8 || len(raw) != 8+4*int(raw[1]) {
		return ""
	}
	var authority uint64
	for _, b := range raw[2:8] {
		authority = authority<<8 | uint64(b)
	}
	sid := fmt.Sprintf("S-%d-%d", raw[0], authority)
	for i := 8; i < len(raw); i += 4 {
		sid += "-" + strconv.FormatUint(uint64(binary.LittleEndian.Uint32(raw[i:i+4])), 10)
	}
	return sid
}

var filterEscapes = strings.NewReplacer("\\", `\5c`, "*", `\2a`, "(", `\28`, ")", `\29`, "\x00", `\00`)

func EscapeFilter(value string) string { return filterEscapes.Replace(value) }
