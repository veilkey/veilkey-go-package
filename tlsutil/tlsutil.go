package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"
)

// DefaultTimeout is the default HTTP client timeout for inter-service communication.
const DefaultTimeout = 30 * time.Second

// NewHTTPClient creates an HTTP client configured for TLS inter-service communication.
func NewHTTPClient(caPath string, insecure bool) (*http.Client, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if caPath != "" {
		caCert, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = pool
	}

	if insecure {
		tlsConfig.InsecureSkipVerify = true
	}

	return &http.Client{
		Timeout: DefaultTimeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}, nil
}

// InitHTTPClientFromEnv creates an HTTP client based on VEILKEY_TLS_CA and
// VEILKEY_TLS_INSECURE environment variables.
func InitHTTPClientFromEnv() *http.Client {
	caPath := os.Getenv("VEILKEY_TLS_CA")
	insecure := os.Getenv("VEILKEY_TLS_INSECURE") == "1"

	if caPath == "" && !insecure {
		return &http.Client{
			Timeout: DefaultTimeout,
		}
	}

	client, err := NewHTTPClient(caPath, insecure)
	if err != nil {
		return &http.Client{
			Timeout: DefaultTimeout,
		}
	}
	return client
}
