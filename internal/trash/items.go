package trash

import (
	"encoding/base64"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const timestampLayout = "2006-01-02T15:04:05-07:00"

type InvalidError string

func (e InvalidError) Error() string { return string(e) }

var versionPrefix = regexp.MustCompile(`(?i)^Copy #[\p{Nd}]+ of `)

func canonicalShare(value string) (string, error) {
	for _, name := range [...]string{"Data", "Private", "FSLogix"} {
		if strings.EqualFold(name, value) {
			return name, nil
		}
	}
	return "", InvalidError("Unbekannte Freigabe")
}

func pathParts(value string) ([]string, error) {
	if !utf8.ValidString(value) || strings.HasPrefix(value, `\`) || strings.ContainsRune(value, 0) {
		return nil, InvalidError("Ungültiger Papierkorbpfad")
	}
	parts := strings.Split(value, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, InvalidError("Ungültiger Papierkorbpfad")
		}
	}
	return parts, nil
}

func EncodeItemID(share, relativePath string) (string, error) {
	share, err := canonicalShare(share)
	if err != nil {
		return "", err
	}
	if _, err := pathParts(relativePath); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString([]byte(share + "\x00" + relativePath)), nil
}

func DecodeItemID(id string) (share, relativePath string, err error) {
	invalid := InvalidError("Ungültige Papierkorb-ID")
	if len(id) == 0 || len(id) > 8192 || strings.ContainsAny(id, "\r\n") {
		return "", "", invalid
	}
	// The original Python decoder permits both alphabets on input.
	id = strings.NewReplacer("+", "-", "/", "_").Replace(id)
	encoding := base64.RawURLEncoding
	if strings.ContainsRune(id, '=') {
		encoding = base64.URLEncoding
	}
	payload, err := encoding.DecodeString(id)
	if err != nil || !utf8.Valid(payload) {
		return "", "", invalid
	}
	share, relativePath, found := strings.Cut(string(payload), "\x00")
	if !found {
		return "", "", invalid
	}
	share, err = canonicalShare(share)
	if err != nil {
		return "", "", err
	}
	if _, err := pathParts(relativePath); err != nil {
		return "", "", err
	}
	return share, relativePath, nil
}

func unversioned(name string) string { return versionPrefix.ReplaceAllString(name, "") }

func ExcludedFilename(filename string) bool {
	name := strings.ToLower(unversioned(filename))
	return strings.HasSuffix(name, ".tmp") || strings.HasPrefix(name, "~$")
}

func originalParts(relative string) ([]string, error) {
	parts, err := pathParts(relative)
	if err != nil {
		return nil, err
	}
	if len(parts) < 2 {
		return nil, InvalidError("Papierkorbeintrag enthält keinen Originalpfad")
	}
	parts = parts[1:]
	parts[len(parts)-1] = unversioned(parts[len(parts)-1])
	if parts[len(parts)-1] == "" {
		return nil, InvalidError("Papierkorbeintrag enthält keinen Dateinamen")
	}
	return parts, nil
}

type Item struct {
	ID        string `json:"id"`
	Share     string `json:"share"`
	Path      string `json:"path"`
	Name      string `json:"name"`
	DeletedBy string `json:"deletedBy"`
	DeletedAt string `json:"deletedAt"`
	ExpiresAt string `json:"expiresAt"`
	Size      int64  `json:"size"`
}

func itemPayload(share, relative string, info unix.Stat_t, retention time.Duration) (Item, error) {
	original, err := originalParts(relative)
	if err != nil {
		return Item{}, err
	}
	id, err := EncodeItemID(share, relative)
	if err != nil {
		return Item{}, err
	}
	deleted := modTime(info).UTC()
	deletedBy, _, _ := strings.Cut(relative, "/")
	return Item{
		ID: id, Share: share, Path: strings.Join(original, "/"), Name: original[len(original)-1],
		DeletedBy: deletedBy, DeletedAt: deleted.Format(timestampLayout),
		ExpiresAt: deleted.Add(retention).Format(timestampLayout), Size: info.Size,
	}, nil
}
