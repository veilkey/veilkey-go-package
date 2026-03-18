package httputil

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// MaxBulkItems is the maximum number of items allowed in a bulk operation.
const MaxBulkItems = 200

// JoinPath joins a base URL with path elements.
// Panics if base is not a valid URL (always a programming error with hardcoded bases).
func JoinPath(base string, elem ...string) string {
	result, err := url.JoinPath(base, elem...)
	if err != nil {
		panic("httputil.JoinPath: " + err.Error())
	}
	return result
}

var validResourceName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// IsValidResourceName reports whether name matches [A-Z_][A-Z0-9_]*.
func IsValidResourceName(name string) bool {
	return validResourceName.MatchString(name)
}

// RespondJSON writes a JSON response with the given status code.
func RespondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("httputil: failed to encode JSON response: %v", err)
	}
}

// RespondError writes a JSON error response.
func RespondError(w http.ResponseWriter, status int, message string) {
	RespondJSON(w, status, map[string]string{"error": message})
}

// DecodeJSON decodes a JSON request body into dst.
func DecodeJSON(r *http.Request, dst any) error {
	return json.NewDecoder(r.Body).Decode(dst)
}

// PathVal returns r.PathValue(key) trimmed of whitespace.
func PathVal(r *http.Request, key string) string {
	return strings.TrimSpace(r.PathValue(key))
}
