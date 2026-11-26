package backup

import (
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

type fileProgress struct {
	Path        string  `json:"path"`
	Percent     float64 `json:"percent"`
	Transferred int64   `json:"transferredBytes"`
	Total       int64   `json:"totalBytes"`
	Detail      string  `json:"detail"`
	updated     time.Time
}

var (
	ansiEscape     = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
	rcloneProgress = regexp.MustCompile(`^\*\s+(.+?):\s+(\d+(?:\.\d+)?)%\s*(.*)$`)
	rsyncProgress  = regexp.MustCompile(`^([\d,.]+(?:\s*[A-Za-z]+)?)\s+(\d+(?:\.\d+)?)%\s+(.*)$`)
	rcloneCopied   = regexp.MustCompile(`\bINFO\s*:\s*(.+): Copied(?:\s|$)`)
	rcloneBytes    = regexp.MustCompile(`/\s*([\d,.]+\s*[A-Za-z]+)`)
	sizePattern    = regexp.MustCompile(`^([\d,.]+)\s*([A-Za-z]*)`)
	thousands      = regexp.MustCompile(`^\d{1,3}(,\d{3})+$`)
)

func parseSize(value string) int64 {
	m := sizePattern.FindStringSubmatch(strings.TrimSpace(value))
	if m == nil {
		return 0
	}
	number := m[1]
	if strings.Contains(number, ".") || thousands.MatchString(number) {
		number = strings.ReplaceAll(number, ",", "")
	} else {
		number = strings.ReplaceAll(number, ",", ".")
	}
	val, err := strconv.ParseFloat(number, 64)
	if err != nil {
		return 0
	}
	unit := strings.ToLower(m[2])
	switch unit {
	case "", "b", "byte", "bytes":
	default:
		power := 1 + strings.IndexByte("kmgtp", unit[0])
		switch unit[1:] {
		case "", "b", "i", "ib", "byte", "bytes":
		default:
			return 0
		}
		if power <= 0 {
			return 0
		}
		val = math.Ldexp(val, 10*power)
	}
	if val >= math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(math.Round(val))
}

func percentFor(count, total int64) float64 {
	if total <= 0 {
		return 0
	}
	return min(100, max(0, float64(count)*100/float64(total)))
}

func formatSize(size int64) string {
	n := float64(size)
	for _, unit := range []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB"} {
		if n < 1024 || unit == "PiB" {
			if unit == "B" {
				return fmt.Sprintf("%d B", size)
			}
			return fmt.Sprintf("%.2f %s", n, unit)
		}
		n /= 1024
	}
	return ""
}

type transferProgress struct {
	source           Source
	total, base      int64
	sourceSize       int64
	maxTransferred   int64
	completedSize    int64
	active           map[string]fileProgress
	completed        map[string]bool
	logged           map[string]time.Time
	lastReport       time.Time
	interval         time.Duration
	log              *runLogger
	status           *runStatus
	interactive      bool
	vanished         bool
	currentRsyncFile string
}

func (p *transferProgress) resetAttempt() {
	p.active = make(map[string]fileProgress)
	p.completed = make(map[string]bool)
	p.logged = make(map[string]time.Time)
	p.completedSize = 0
	p.currentRsyncFile = ""
	p.vanished = false
}

func (p *transferProgress) sourceFileSize(name string) int64 {
	name = filepath.Clean(name)
	if !filepath.IsLocal(name) {
		return 0
	}
	info, err := os.Lstat(filepath.Join(p.source.Path, name))
	if err == nil && info.Mode().IsRegular() {
		return info.Size()
	}
	return 0
}

func (p *transferProgress) observe(command, line string) {
	var progress fileProgress
	if command == "rclone" {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "failed to open source object") && strings.Contains(lower, "no such file or directory") {
			p.vanished = true
		}
		if m := rcloneProgress.FindStringSubmatch(line); m != nil {
			progress.Path, progress.Detail = strings.TrimSpace(m[1]), m[3]
			progress.Percent, _ = strconv.ParseFloat(m[2], 64)
			if size := rcloneBytes.FindStringSubmatch(m[3]); size != nil {
				progress.Total = parseSize(size[1])
			}
			if progress.Total == 0 {
				progress.Total = p.sourceFileSize(progress.Path)
			}
			progress.Transferred = int64(math.Round(float64(progress.Total) * min(progress.Percent, 100) / 100))
		} else if m := rcloneCopied.FindStringSubmatch(line); m != nil {
			progress.Path, progress.Percent, progress.Detail = m[1], 100, "Copied"
			progress.Total = p.sourceFileSize(progress.Path)
			progress.Transferred = progress.Total
		}
	} else if m := rsyncProgress.FindStringSubmatch(line); m != nil {
		progress.Path, progress.Detail = p.currentRsyncFile, m[3]
		progress.Percent, _ = strconv.ParseFloat(m[2], 64)
		progress.Transferred = parseSize(m[1])
		progress.Total = p.sourceFileSize(progress.Path)
		if progress.Total == 0 && progress.Percent > 0 {
			progress.Total = int64(math.Round(float64(progress.Transferred) * 100 / progress.Percent))
		}
		progress.Total = max(progress.Total, progress.Transferred)
	} else if !strings.HasSuffix(line, "/") && !ignoredRsyncLine(line) {
		p.currentRsyncFile = line
	}

	if progress.Path == "" || p.completed[progress.Path] {
		return
	}
	if progress.Percent > 100 {
		progress.Percent = 100
	}
	now := time.Now()
	progress.updated = now
	if progress.Percent >= 100 {
		p.completed[progress.Path] = true
		p.completedSize = min(p.sourceSize, p.completedSize+progress.Total)
		delete(p.active, progress.Path)
	} else {
		p.active[progress.Path] = progress
	}
	if progress.Percent >= 100 || now.Sub(p.logged[progress.Path]) >= p.interval {
		p.log.log(!p.interactive, "Upload progress %s -> %s: %s %.2f%% (%s / %s) (%s)",
			p.source.Path, p.source.Destination, progress.Path, progress.Percent,
			formatSize(progress.Transferred), formatSize(progress.Total), progress.Detail)
		p.logged[progress.Path] = now
	}
	transferred := p.completedSize
	for _, active := range p.active {
		transferred = min(p.sourceSize, transferred+active.Transferred)
	}
	p.maxTransferred = max(p.maxTransferred, transferred)
	p.report(now, false)
}

func ignoredRsyncLine(line string) bool {
	for _, prefix := range []string{"sending incremental file list", "receiving incremental file list", "sent ", "total size is ", "deleting "} {
		if strings.HasPrefix(strings.ToLower(line), prefix) {
			return true
		}
	}
	return false
}

func (p *transferProgress) report(now time.Time, force bool) {
	if !force && now.Sub(p.lastReport) < p.interval {
		return
	}
	p.lastReport = now
	active := make([]fileProgress, 0, len(p.active))
	for _, progress := range p.active {
		if now.Sub(progress.updated) <= max(2*time.Second, 2*p.interval) {
			active = append(active, progress)
		}
	}
	sort.Slice(active, func(i, j int) bool { return active[i].updated.After(active[j].updated) })
	active = active[:min(len(active), 12)]
	count := p.base + p.maxTransferred
	percent := math.Round(percentFor(count, p.total)*100) / 100
	p.status.write(map[string]any{"state": "running", "currentSource": p.source.Destination, "percent": percent,
		"totalBytes": p.total, "transferredBytes": count, "activeFiles": active, "message": "Syncing " + p.source.Path})
	p.log.log(!p.interactive, "Total upload progress: %.2f%% (%s / %s)", percent, formatSize(count), formatSize(p.total))
	if p.interactive {
		width := int(percent * 28 / 100)
		fmt.Fprintf(p.log.stderr, "\r[backup] TOTAL [%s%s] %.2f%% (%s / %s)\x1b[K", strings.Repeat("#", width), strings.Repeat("-", 28-width), percent, formatSize(count), formatSize(p.total))
	}
}

func isTTY(f *os.File) bool {
	var state syscall.Termios
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), syscall.TCGETS, uintptr(unsafe.Pointer(&state)))
	return err == 0
}

type progressOutput struct {
	name    string
	current []byte
	records []string
	observe func(string, string)
}

func (w *progressOutput) flush() {
	line := strings.TrimSpace(ansiEscape.ReplaceAllString(string(w.current), ""))
	w.current = w.current[:0]
	if line == "" {
		return
	}
	w.observe(w.name, line)
	if len(w.records) == 50 {
		copy(w.records, w.records[1:])
		w.records = w.records[:49]
	}
	w.records = append(w.records, line[:min(len(line), 1000)])
}

func (w *progressOutput) Write(data []byte) (int, error) {
	for _, ch := range data {
		if ch == '\n' || ch == '\r' {
			w.flush()
		} else if len(w.current) < 65536 {
			w.current = append(w.current, ch)
		}
	}
	return len(data), nil
}

func runTransfer(cmd *exec.Cmd, progress *transferProgress) commandResult {
	output := &progressOutput{name: filepath.Base(cmd.Path), observe: progress.observe}
	cmd.Stdout, cmd.Stderr = output, output
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	output.flush()
	return commandResult{stdout: strings.Join(output.records, "\n"), err: err}
}
