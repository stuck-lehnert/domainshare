package documents

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type credentials struct {
	uid, gid int
}

func documentCredentials() (credentials, error) {
	account, err := user.Lookup("document-ocr")
	if err != nil {
		return credentials{}, err
	}
	uid, uidErr := strconv.Atoi(account.Uid)
	gid, gidErr := strconv.Atoi(account.Gid)
	if uidErr != nil || gidErr != nil || uid <= 0 || gid <= 0 || uid == os.Geteuid() {
		return credentials{}, errors.New("invalid dedicated document-ocr credentials")
	}
	return credentials{uid: uid, gid: gid}, nil
}

func (index indexer) runJob(ctx context.Context, row catalogRow, source indexSource, phase string) (*extractionResult, error) {
	config := extractionConfig{
		Extension: row.Extension, Phase: phase, Timeout: 120,
		MaxPages:     indexSetting("DOCUMENT_MAX_PDF_PAGES", 500, 1, 5000),
		DPI:          indexSetting("DOCUMENT_OCR_DPI", 300, 150, 400),
		MaxDimension: indexSetting("DOCUMENT_OCR_MAX_DIMENSION", 3500, 1500, 5000),
		PageTimeout:  indexSetting("DOCUMENT_OCR_PAGE_TIMEOUT_SECONDS", 30, 5, 120),
	}
	config.Language = os.Getenv("DOCUMENT_OCR_LANGUAGE")
	if config.Language == "" {
		config.Language = "deu+eng"
	}
	if phase == "ocr" {
		config.Timeout = indexSetting("DOCUMENT_OCR_TIMEOUT_SECONDS", 600, 30, 3600)
	}

	workspace, err := os.MkdirTemp(index.jobsRoot, "job-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(workspace)

	if err := index.stageConfig(workspace, config); err != nil {
		return nil, err
	}
	staged, err := index.stageOriginal(ctx, workspace, source, row)
	if err != nil || !staged {
		return nil, err
	}
	if err := os.Chown(workspace, index.credentials.uid, index.credentials.gid); err != nil {
		return nil, err
	}

	processErr := index.runHelper(ctx, workspace, config.Timeout)
	if processErr != nil {
		var processExit *exec.ExitError
		if !errors.As(processErr, &processExit) {
			return nil, processErr
		}
	}

	resultFile, info, err := openFile(workspace, "result.json", nil)
	if err != nil {
		if processErr != nil {
			return nil, fmt.Errorf("document extraction failed: %w", processErr)
		}
		return nil, err
	}
	defer resultFile.Close()
	const maxResponse = maxText*6 + 4096
	if info.Size > maxResponse {
		return nil, errors.New("extraction response too large")
	}
	var result extractionResult
	if err := json.NewDecoder(io.LimitReader(resultFile, maxResponse)).Decode(&result); err != nil {
		return nil, err
	}
	if result.Error != "" {
		return nil, errors.New(result.Error)
	}
	if processErr != nil {
		return nil, processErr
	}
	if result.Pages < 0 || result.Pages > config.MaxPages {
		return nil, errors.New("invalid page count from extractor")
	}

	file, current, err := openFile(source.root, row.Path, nil)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	file.Close()
	if fingerprint(current) != row.fingerprint {
		return nil, nil
	}

	result.preview, err = index.storePreview(workspace, row)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (index indexer) stageConfig(workspace string, config extractionConfig) error {
	file, err := os.OpenFile(filepath.Join(workspace, "config.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := json.NewEncoder(file).Encode(config); err != nil {
		return err
	}
	return file.Chown(index.credentials.uid, index.credentials.gid)
}

func (index indexer) stageOriginal(ctx context.Context, workspace string, source indexSource, row catalogRow) (bool, error) {
	original, info, err := openFile(source.root, row.Path, nil)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer original.Close()
	if fingerprint(info) != row.fingerprint || info.Size != row.Size {
		return false, nil
	}

	target, err := os.OpenFile(filepath.Join(workspace, "input"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o400)
	if err != nil {
		return false, err
	}
	defer target.Close()
	remaining := row.Size
	buffer := make([]byte, 1<<20)
	for remaining > 0 {
		if err := index.cancelled(ctx); err != nil {
			return false, err
		}
		chunk := buffer[:min(int64(len(buffer)), remaining)]
		if _, err := io.ReadFull(original, chunk); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return false, nil
			}
			return false, err
		}
		if _, err := target.Write(chunk); err != nil {
			return false, err
		}
		remaining -= int64(len(chunk))
	}
	final, err := fdStat(int(original.Fd()))
	if err != nil || fingerprint(final) != row.fingerprint {
		return false, err
	}
	return true, target.Chown(index.credentials.uid, index.credentials.gid)
}

func (index indexer) runHelper(ctx context.Context, workspace string, timeout int) error {
	if err := index.cancelled(ctx); err != nil {
		return err
	}

	cmd := exec.Command(index.executable, "document-extract", workspace)
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "HOME=" + workspace,
		"TMPDIR=" + workspace, "OMP_THREAD_LIMIT=1", "GOMAXPROCS=1"}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true, Pdeathsig: unix.SIGKILL,
		Credential: &syscall.Credential{Uid: uint32(index.credentials.uid), Gid: uint32(index.credentials.gid), Groups: []uint32{}},
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	pid := cmd.Process.Pid
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	stop := func(reason error) error {
		_ = unix.Kill(-pid, unix.SIGKILL)
		<-done
		return reason
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(time.Duration(timeout) * time.Second)
	defer deadline.Stop()

	for {
		select {
		case err := <-done:
			_ = unix.Kill(-pid, unix.SIGKILL)
			return err
		case <-ctx.Done():
			return stop(ctx.Err())
		case <-deadline.C:
			return stop(errors.New("Extraction timed out"))
		case <-ticker.C:
			if err := index.cancelled(ctx); err != nil {
				return stop(err)
			}
		}
	}
}

func (index indexer) storePreview(workspace string, row catalogRow) (string, error) {
	file, info, err := openFile(workspace, "preview.jpg", nil)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer file.Close()

	var magic [2]byte
	_, err = io.ReadFull(file, magic[:])
	if err != nil || info.Size > 16<<20 || magic != [2]byte{0xff, 0xd8} {
		return "", errors.New("Invalid preview")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}

	previews := filepath.Join(index.DocumentRoot, "previews")
	if err := os.Mkdir(previews, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	dir, _, err := openDirectory(previews, nil, nil)
	if err != nil {
		return "", err
	}
	defer dir.Close()
	if err := dir.Chmod(0o700); err != nil {
		return "", err
	}

	output, err := os.CreateTemp(previews, ".preview-")
	if err != nil {
		return "", err
	}
	defer os.Remove(output.Name())
	_, copyErr := io.CopyN(output, file, info.Size)
	if err := errors.Join(copyErr, output.Close()); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(row.ID + row.fingerprint))
	name := hex.EncodeToString(sum[:16]) + ".jpg"
	if err := os.Rename(output.Name(), filepath.Join(previews, name)); err != nil {
		return "", err
	}
	return name, nil
}
