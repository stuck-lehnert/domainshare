// Package tlssetup maintains HTTPS certificates and first-run status files.
package tlssetup

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/stuck-lehnert/domainshare/internal/config"
	"github.com/stuck-lehnert/domainshare/internal/securefile"
)

type identity struct {
	Hostname string `json:"hostname"`
	Mode     string `json:"mode"`
}

type Status struct {
	State   string `json:"state"`
	Message string `json:"message,omitempty"`
}

func BootstrapMarker(certPath string) string {
	return filepath.Join(filepath.Dir(certPath), "bootstrap-certificate")
}

func ReadStatus(root string) Status {
	var status Status
	payload, err := os.ReadFile(filepath.Join(root, "https-status.json"))
	if err != nil || json.Unmarshal(payload, &status) != nil || status.State == "" {
		return Status{State: "waiting"}
	}
	return status
}

func WriteStatus(root string, status Status) error {
	return writeJSON(filepath.Join(root, "https-status.json"), status)
}

func writeJSON(path string, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return securefile.WritePrivate(path, payload)
}

// Prepare keeps valid certificates, installs uploaded ones, or generates a
// private bootstrap pair. ACME issuance remains the responsibility of step.
func Prepare(ctx context.Context, store *config.Store) error {
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		return err
	}
	environment, err := store.Environment(snapshot, true)
	if err != nil {
		return err
	}
	return prepare(snapshot, environment, time.Now())
}

func prepare(snapshot config.Snapshot, environment map[string]string, now time.Time) error {
	certPath, keyPath := environment["WEB_TLS_CERT_FILE"], environment["WEB_TLS_KEY_FILE"]
	marker := BootstrapMarker(certPath)
	identityPath := filepath.Join(filepath.Dir(certPath), "configuration.json")
	current := identity{Hostname: snapshot.Values.String("WEB_HOSTNAME"), Mode: snapshot.Values.String("WEB_TLS_MODE")}
	var previous identity
	known := false
	if payload, err := os.ReadFile(identityPath); err == nil {
		known = json.Unmarshal(payload, &previous) == nil
	}

	certPEM, keyPEM := snapshot.Values.String("WEB_TLS_CERT_PEM"), snapshot.Values.String("WEB_TLS_KEY_PEM")
	if current.Mode == "files" && certPEM != "" && keyPEM != "" {
		if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
			return errors.New("HTTPS-Zertifikat und privater Schlüssel sind ungültig oder passen nicht zusammen")
		}
		if !fileMatches(certPath, certPEM) || !fileMatches(keyPath, keyPEM) {
			if err := writePair(certPath, keyPath, []byte(certPEM), []byte(keyPEM)); err != nil {
				return err
			}
		}
		if err := os.Remove(marker); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return writeJSON(identityPath, current)
	}

	if !known || previous == current {
		if pair, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil && len(pair.Certificate) > 0 {
			leaf, err := x509.ParseCertificate(pair.Certificate[0])
			if err == nil && (current.Mode != "self-signed" || leaf.NotAfter.After(now.Add(7*24*time.Hour))) {
				return writeJSON(identityPath, current)
			}
		}
	}

	host := current.Hostname
	if host == "" {
		host = "localhost"
	}
	cert, key, err := generate(host, now)
	if err != nil {
		return err
	}
	if err := writePair(certPath, keyPath, cert, key); err != nil {
		return err
	}
	if err := securefile.WritePrivate(marker, []byte("1")); err != nil {
		return err
	}
	return writeJSON(identityPath, current)
}

func fileMatches(path, contents string) bool {
	data, err := os.ReadFile(path)
	return err == nil && string(data) == contents
}

func writePair(certPath, keyPath string, cert, key []byte) error {
	if err := securefile.WritePrivate(keyPath, key); err != nil {
		return err
	}
	return securefile.WritePrivate(certPath, cert)
}

func generate(host string, now time.Time) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	serial.Add(serial, big.NewInt(1))

	certificate := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	machine, _ := os.Hostname()
	for _, name := range []string{host, machine} {
		if address := net.ParseIP(name); address != nil {
			if !slices.ContainsFunc(certificate.IPAddresses, address.Equal) {
				certificate.IPAddresses = append(certificate.IPAddresses, address)
			}
		} else if name != "" && !slices.Contains(certificate.DNSNames, name) {
			certificate.DNSNames = append(certificate.DNSNames, name)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}
