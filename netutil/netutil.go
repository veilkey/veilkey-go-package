package netutil

import (
	"net"
	"strings"
)

// NormalizeRemoteAddr extracts the IP from a host:port string.
// Returns the raw string if parsing fails.
func NormalizeRemoteAddr(remote string) string {
	raw := strings.TrimSpace(remote)
	if raw == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(raw)
	if err == nil && host != "" {
		return host
	}
	return raw
}

// FormatVaultID returns "name:hash8" identifying a vault.
// Truncates hash to 8 characters.
func FormatVaultID(name, hash string) string {
	h := strings.TrimSpace(hash)
	if len(h) > 8 {
		h = h[:8]
	}
	n := strings.TrimSpace(name)
	if n == "" {
		return h
	}
	if h == "" {
		return n
	}
	return n + ":" + h
}
