package webapi

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func setSecurityHeaders(headers http.Header, pdfViewer bool, cache string) {
	content := "default-src 'self'; connect-src 'self'; img-src 'self' data:; "
	ancestors := "'none'"
	if pdfViewer {
		content = "default-src 'self'; connect-src 'self' blob: data:; img-src 'self' data: blob:; " +
			"worker-src 'self' blob:; font-src 'self' data: blob:; media-src blob:; "
		ancestors = "'self'"
	}
	policy := content + "style-src 'self'; script-src 'self' 'wasm-unsafe-eval'; " +
		"base-uri 'none'; frame-ancestors " + ancestors + "; form-action 'self'"

	headers.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	headers.Set("Content-Security-Policy", policy)
	headers.Set("X-Content-Type-Options", "nosniff")
	headers.Set("Referrer-Policy", "no-referrer")
	headers.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	headers.Set("Cache-Control", cache)
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	body, err := json.Marshal(value)
	if err != nil {
		body, _ = json.Marshal(map[string]string{"error": "Antwort konnte nicht erstellt werden"})
		status = http.StatusInternalServerError
	}

	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Content-Length", strconv.Itoa(len(body)))
	writer.WriteHeader(status)
	_, _ = writer.Write(body)
}

func writeError(writer http.ResponseWriter, status int, message string) {
	writeJSON(writer, status, map[string]string{"error": message})
}

var byteRange = regexp.MustCompile(`^bytes=([0-9]*)-([0-9]*)$`)

func rangeNumber(value string) int64 {
	number, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return math.MaxInt64
	}
	return number
}

func fileRange(values []string, size int64) (start, end int64, valid bool) {
	if len(values) != 1 || len(values[0]) > 128 || size <= 0 {
		return 0, 0, false
	}

	parts := byteRange.FindStringSubmatch(values[0])
	if parts == nil || (parts[1] == "" && parts[2] == "") {
		return 0, 0, false
	}

	end = size - 1
	if parts[1] == "" {
		length := rangeNumber(parts[2])
		if length == 0 {
			return 0, 0, false
		}
		start = max(0, size-length)
	} else {
		start = rangeNumber(parts[1])
		if parts[2] != "" {
			end = min(end, rangeNumber(parts[2]))
		}
	}
	return start, end, start <= end
}

func writeFile(writer http.ResponseWriter, request *http.Request, file io.ReaderAt, size int64, media, name, disposition string, allowRange bool) {
	start, end, status := int64(0), size-1, http.StatusOK
	headers := writer.Header()
	if ranges := request.Header.Values("Range"); allowRange && len(ranges) != 0 {
		var valid bool
		start, end, valid = fileRange(ranges, size)
		if !valid {
			headers.Set("Content-Range", fmt.Sprintf("bytes */%d", size))
			headers.Set("Content-Length", "0")
			writer.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		status = http.StatusPartialContent
		headers.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, size))
	}

	length := end - start + 1
	headers.Set("Content-Length", strconv.FormatInt(length, 10))
	headers.Set("Content-Type", media)
	if allowRange {
		headers.Set("Accept-Ranges", "bytes")
	}
	if name != "" {
		encoded := strings.ReplaceAll(url.QueryEscape(name), "+", "%20")
		headers.Set("Content-Disposition", disposition+"; filename*=UTF-8''"+encoded)
	}

	writer.WriteHeader(status)
	output := downloadWriter{writer, http.NewResponseController(writer)}
	_, _ = io.Copy(output, io.NewSectionReader(file, start, length))
}

// Large downloads can take longer than the ordinary response timeout. Give
// each chunk a fresh deadline without letting a stalled client hold a slot.
type downloadWriter struct {
	writer     http.ResponseWriter
	controller *http.ResponseController
}

func (output downloadWriter) Write(chunk []byte) (int, error) {
	_ = output.controller.SetWriteDeadline(time.Now().Add(responseWriteTimeout))
	return output.writer.Write(chunk)
}
