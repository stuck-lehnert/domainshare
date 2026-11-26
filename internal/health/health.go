// Package health probes the container's own HTTPS listener.
package health

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"
)

const DefaultPort = 8443

func Check(ctx context.Context, port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid healthcheck port")
	}

	// The address is fixed to local loopback and redirects are rejected. The
	// listener can use a temporary self-signed certificate during onboarding.
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}, // #nosec G402 -- local probe only
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+address+"/healthz", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("local HTTPS healthcheck returned %d", response.StatusCode)
	}
	return nil
}
