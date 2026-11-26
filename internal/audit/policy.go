// Package audit ingests Samba full_audit messages and queries their SQLite history.
package audit

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/text/cases"
)

const (
	secondLayout      = "2006-01-02T15:04:05-07:00"
	millisecondLayout = "2006-01-02T15:04:05.000-07:00"
	dayLayout         = "2006-01-02"
	daySeconds        = 86400
)

// Event is a normalized audit record. On query, Operation is the normalized Action.
type Event struct {
	ID         int64  `json:"id"`
	Timestamp  string `json:"timestamp"`
	IngestedAt string `json:"ingestedAt"`
	User       string `json:"user"`
	ClientIP   string `json:"clientIp"`
	Client     string `json:"client"`
	Share      string `json:"share"`
	Operation  string `json:"operation"`
	Action     string `json:"action"`
	Result     string `json:"result"`
	Success    bool   `json:"success"`
	Path       string `json:"path"`
	Source     string `json:"source"`
}

func actionFor(operation string) string {
	switch fold(strings.TrimSpace(operation)) {
	case "read", "pread", "pread_recv", "pread_send", "sendfile", "offload_read_recv", "offload_read_send":
		return "read"
	case "write", "pwrite", "pwrite_recv", "pwrite_send", "recvfile", "offload_write_recv", "offload_write_send":
		return "write"
	case "renameat", "rename":
		return "move"
	case "unlinkat", "unlink", "rmdir":
		return "delete"
	default:
		return ""
	}
}

var caseFolder = cases.Fold()

func fold(value string) string {
	return caseFolder.String(value)
}

func accountName(user string) string {
	user = strings.TrimSpace(user)
	user = user[strings.LastIndexByte(user, '\\')+1:]
	account, _, _ := strings.Cut(user, "@")
	return fold(account)
}

func excludedAccount(user string) bool {
	account := accountName(user)
	return account == "krbtgt" || strings.HasPrefix(account, "msol_")
}

func env(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func skippedSuffixes() []string {
	var suffixes []string
	for _, value := range strings.Split(env("AUDIT_SKIP_USER_SUFFIXES", "_svc,_ServiceAcc"), ",") {
		if suffix := fold(strings.TrimSpace(value)); suffix != "" {
			suffixes = append(suffixes, suffix)
		}
	}
	return suffixes
}

func skipUser(user string, suffixes []string) bool {
	account := accountName(user)
	for _, suffix := range suffixes {
		if strings.HasSuffix(account, suffix) {
			return true
		}
	}
	return false
}

func dedupCutoff(now time.Time) int64 {
	const defaultWindow = 2 * daySeconds
	configured := env("AUDIT_DEDUP_WINDOW_SECONDS", env("AUDIT_READ_DEDUP_WINDOW_SECONDS", "172800"))
	window, err := strconv.ParseInt(strings.TrimSpace(configured), 10, 64)
	if err != nil {
		window = defaultWindow
	}
	return now.Unix() - max(1, window)
}

func eventTime(value string) (time.Time, error) {
	// Samba writes RFC3339 with a numeric UTC offset. Accept legacy naïve
	// timestamps (UTC) and date-only values as the Python reader did.
	if len(value) > 10 && value[10] != 'T' {
		value = value[:10] + "T" + value[11:]
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02T15:04", dayLayout} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid audit timestamp %q", value)
}

func unixSecond(value time.Time) int64 {
	second := value.Unix()
	if second < 0 && value.Nanosecond() != 0 {
		return second + 1 // Python int(timestamp) truncates toward zero.
	}
	return second
}

func dayNumber(second int64) int64 {
	day := second / daySeconds
	if second%daySeconds < 0 {
		day--
	}
	return day
}

func dedupEligible(event Event) bool {
	return fold(event.Action) == "read" || fold(event.Share) == "fslogix"
}

// fingerprint must remain byte-for-byte compatible with audit_event_dedup
// populated by Python. In particular, the digest size is part of BLAKE2b's
// initialization and cannot be emulated by truncating a longer digest.
func fingerprint(event Event, second string) [16]byte {
	status, failureResult := "success", ""
	if !event.Success {
		status, failureResult = "failure", event.Result
	}
	values := [...]string{
		second, fold(event.Action), event.User, event.ClientIP,
		event.Share, event.Path, status, failureResult,
	}

	digest, err := blake2b.New(16, nil)
	if err != nil {
		panic(err) // BLAKE2b-128 with no key is a fixed, valid configuration.
	}
	var length [4]byte
	for _, value := range values {
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = digest.Write(length[:])
		_, _ = digest.Write([]byte(value))
	}
	return [16]byte(digest.Sum(nil))
}
