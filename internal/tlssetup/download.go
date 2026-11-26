package tlssetup

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/stuck-lehnert/domainshare/internal/securefile"
)

const caBundleLimit = 4 * 1024 * 1024

// DownloadCABundle is the explicitly configured one-time trust bootstrap.
// Never allow a redirect to leave HTTPS or disclose the source URL in errors.
func DownloadCABundle(ctx context.Context, address, output string, insecure bool) error {
	parsed, err := url.Parse(address)
	if err != nil || !validCAURL(parsed) {
		return errors.New("CA bundle URL must use HTTPS without embedded credentials")
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(request *http.Request, previous []*http.Request) error {
			if len(previous) >= 5 || !validCAURL(request.URL) {
				return errors.New("invalid CA bundle redirect")
			}
			return nil
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return errors.New("invalid CA bundle request")
	}
	request.Header.Set("User-Agent", "DomainShare-CA-Bootstrap/1")
	response, err := client.Do(request)
	if err != nil {
		return errors.New("CA bundle download failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("CA bundle server did not return HTTP 200")
	}

	payload, err := io.ReadAll(io.LimitReader(response.Body, caBundleLimit+1))
	if err != nil || len(payload) > caBundleLimit || !validCABundle(payload) {
		return errors.New("CA bundle is empty, invalid, or larger than 4 MiB")
	}
	return securefile.WritePrivate(output, payload)
}

func validCAURL(value *url.URL) bool {
	return value != nil && value.Scheme == "https" && value.Hostname() != "" && value.User == nil
}

func validCABundle(data []byte) bool {
	rest := bytes.TrimSpace(data)
	if len(rest) == 0 {
		return false
	}
	for len(rest) > 0 {
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return false
		}
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" {
			return false
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA {
			return false
		}
		rest = bytes.TrimSpace(next)
	}
	return true
}
