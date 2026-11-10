package tlsutil

import (
	"crypto/tls"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func checkTLSConfig(t *testing.T, client *http.Client, insecure bool) *tls.Config {
	t.Helper()
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil {
		t.Fatal("client must use an explicit TLS configuration")
	}
	t.Cleanup(transport.CloseIdleConnections)
	config := transport.TLSClientConfig
	if config.InsecureSkipVerify != insecure {
		t.Fatalf("InsecureSkipVerify=%v, want %v", config.InsecureSkipVerify, insecure)
	}
	if config.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion=%d, want TLS 1.2", config.MinVersion)
	}
	if client.Timeout != DefaultTimeout {
		t.Fatalf("Timeout=%v, want %v", client.Timeout, DefaultTimeout)
	}
	return config
}

func TestNewHTTPClientRequiresExplicitInsecure(t *testing.T) {
	for _, insecure := range []bool{false, true} {
		client, err := NewHTTPClient("", insecure)
		if err != nil {
			t.Fatal(err)
		}
		checkTLSConfig(t, client, insecure)
	}
}

func TestInitHTTPClientFromEnvSecureDefaults(t *testing.T) {
	for _, value := range []string{"", "0", "false", "true", "yes", "01", " 1", "1"} {
		t.Run("insecure="+value, func(t *testing.T) {
			t.Setenv("VEILKEY_TLS_CA", "")
			t.Setenv("VEILKEY_TLS_INSECURE", value)
			checkTLSConfig(t, InitHTTPClientFromEnv(), value == "1")
		})
	}
	t.Run("unset", func(t *testing.T) {
		t.Setenv("VEILKEY_TLS_CA", "")
		t.Setenv("VEILKEY_TLS_INSECURE", "")
		if err := os.Unsetenv("VEILKEY_TLS_CA"); err != nil {
			t.Fatal(err)
		}
		if err := os.Unsetenv("VEILKEY_TLS_INSECURE"); err != nil {
			t.Fatal(err)
		}
		checkTLSConfig(t, InitHTTPClientFromEnv(), false)
	})
}

func TestInvalidCAKeepsVerificationEnabled(t *testing.T) {
	invalid := filepath.Join(t.TempDir(), "invalid.pem")
	if err := os.WriteFile(invalid, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{invalid, filepath.Join(t.TempDir(), "missing.pem")} {
		for _, insecure := range []string{"0", "1"} {
			t.Run(filepath.Base(path)+"/insecure="+insecure, func(t *testing.T) {
				if client, err := NewHTTPClient(path, insecure == "1"); err == nil || client != nil {
					t.Fatal("NewHTTPClient must reject an unreadable or invalid CA")
				}
				t.Setenv("VEILKEY_TLS_CA", path)
				t.Setenv("VEILKEY_TLS_INSECURE", insecure)
				checkTLSConfig(t, InitHTTPClientFromEnv(), false)
			})
		}
	}
}

func TestHTTPClientsVerifyCertificates(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caPath, cert, 0600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name     string
		fromEnv  bool
		caPath   string
		insecure bool
		wantOK   bool
	}{
		{name: "constructor/default"},
		{name: "constructor/custom_CA", caPath: caPath, wantOK: true},
		{name: "constructor/explicit_insecure", insecure: true, wantOK: true},
		{name: "environment/default", fromEnv: true},
		{name: "environment/custom_CA", fromEnv: true, caPath: caPath, wantOK: true},
		{name: "environment/explicit_insecure", fromEnv: true, insecure: true, wantOK: true},
		{name: "environment/invalid_CA", fromEnv: true, caPath: filepath.Join(t.TempDir(), "missing.pem")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var client *http.Client
			if tc.fromEnv {
				t.Setenv("VEILKEY_TLS_CA", tc.caPath)
				insecure := "0"
				if tc.insecure {
					insecure = "1"
				}
				t.Setenv("VEILKEY_TLS_INSECURE", insecure)
				client = InitHTTPClientFromEnv()
			} else {
				var err error
				client, err = NewHTTPClient(tc.caPath, tc.insecure)
				if err != nil {
					t.Fatal(err)
				}
			}
			config := checkTLSConfig(t, client, tc.insecure)
			response, err := client.Get(server.URL)
			if err != nil {
				if tc.wantOK {
					t.Fatalf("trusted connection failed: %v", err)
				}
				return
			}
			if err := response.Body.Close(); err != nil {
				t.Fatal(err)
			}
			if !tc.wantOK {
				t.Fatal("client accepted an untrusted certificate")
			}
			if response.StatusCode != http.StatusNoContent {
				t.Fatalf("unexpected response status: %d", response.StatusCode)
			}
			if !tc.insecure {
				client.CloseIdleConnections()
				config.ServerName = "wrong-host.invalid"
				response, err = client.Get(server.URL)
				if err == nil {
					_ = response.Body.Close()
					t.Fatal("client accepted a certificate for a different hostname")
				}
			}
		})
	}
}
