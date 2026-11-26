package webapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type downloadRecorder struct {
	*httptest.ResponseRecorder
	deadline time.Time
	writes   int
	t        *testing.T
}

func (recorder *downloadRecorder) SetWriteDeadline(deadline time.Time) error {
	recorder.deadline = deadline
	return nil
}

func (recorder *downloadRecorder) Write(chunk []byte) (int, error) {
	if !recorder.deadline.After(time.Now()) {
		recorder.t.Fatal("download chunk was written without a fresh deadline")
	}

	recorder.deadline = time.Time{}
	recorder.writes++
	return recorder.ResponseRecorder.Write(chunk)
}

func TestDownloadSetsDeadlineForEachChunk(t *testing.T) {
	data := bytes.Repeat([]byte("download fixture\n"), 8192)
	writer := &downloadRecorder{ResponseRecorder: httptest.NewRecorder(), t: t}
	request := httptest.NewRequest(http.MethodGet, "/download", nil)

	writeFile(writer, request, bytes.NewReader(data), int64(len(data)), "text/plain", "fixture.txt", "attachment", true)

	if writer.writes < 2 || !bytes.Equal(writer.Body.Bytes(), data) {
		t.Fatalf("expected multiple chunks with the original content, got %d chunks", writer.writes)
	}
}
