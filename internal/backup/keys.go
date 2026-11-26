package backup

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// KeyFormat is the original versioned derivation salt. Changing it would make
// existing recovery phrases unusable.
const KeyFormat = "adfs-backup-archive-v1"

//go:embed wordlist/english.txt
var wordlist string

var words = strings.Fields(wordlist)
var wordIDs = func() map[string]uint16 {
	ids := make(map[string]uint16, len(words))
	for i, word := range words {
		ids[word] = uint16(i)
	}
	if len(words) != 2048 || len(ids) != 2048 {
		panic("invalid BIP39 wordlist")
	}
	return ids
}()

// Key contains secrets. Only KeyID and Format may be exposed after confirming
// the recovery phrase.
type Key struct {
	Phrase   string `json:"-"`
	Password string `json:"-"`
	KeyID    string `json:"keyId"`
	Format   string `json:"format"`
}

func phraseFromEntropy(entropy []byte) string {
	checksum := sha256.Sum256(entropy)
	bits := append(append([]byte(nil), entropy...), checksum[0])
	count := len(entropy) * 3 / 4
	phrase := make([]string, count)
	for i := range phrase {
		var id uint16
		for j := 0; j < 11; j++ {
			bit := 11*i + j
			id = (id << 1) | uint16((bits[bit/8]>>(7-bit%8))&1)
		}
		phrase[i] = words[id]
	}
	return strings.Join(phrase, " ")
}

// NormalizePhrase normalizes and validates a BIP39 English recovery phrase.
func NormalizePhrase(phrase string) (string, error) {
	fields := strings.Fields(strings.ToLower(norm.NFKD.String(phrase)))
	count := len(fields)
	if count < 12 || count > 24 || count%3 != 0 {
		return "", errors.New("Ungültige Wiederherstellungsphrase")
	}

	entropy := make([]byte, count*4/3)
	for i, word := range fields {
		id, ok := wordIDs[word]
		if !ok {
			return "", errors.New("Ungültige Wiederherstellungsphrase")
		}
		for j := 0; j < 11; j++ {
			bit := 11*i + j
			if bit < len(entropy)*8 {
				entropy[bit/8] |= byte((id>>(10-j))&1) << (7 - bit%8)
			}
		}
	}

	normal := strings.Join(fields, " ")
	if phraseFromEntropy(entropy) != normal {
		return "", errors.New("Prüfsumme der Wiederherstellungsphrase stimmt nicht")
	}
	return normal, nil
}

// ArchiveKey derives the original v1 archive password from a recovery phrase.
func ArchiveKey(phrase string) (string, error) {
	normal, err := NormalizePhrase(phrase)
	if err != nil {
		return "", err
	}
	seed, err := pbkdf2.Key(sha512.New, normal, []byte("mnemonic"), 2048, 64)
	if err != nil {
		return "", err
	}
	password, err := pbkdf2.Key(sha512.New, string(seed), []byte(KeyFormat), 1, 32)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(password), nil
}

// GenerateKey creates a new 24-word recovery phrase and its archive key.
func GenerateKey() (Key, error) {
	entropy := make([]byte, 32)
	if _, err := rand.Read(entropy); err != nil {
		return Key{}, err
	}
	phrase := phraseFromEntropy(entropy)
	password, err := ArchiveKey(phrase)
	if err != nil {
		return Key{}, err
	}
	id := sha256.Sum256([]byte(password))
	return Key{Phrase: phrase, Password: password, KeyID: hex.EncodeToString(id[:12]), Format: KeyFormat}, nil
}
