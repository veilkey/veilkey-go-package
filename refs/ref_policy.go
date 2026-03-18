package refs

import "fmt"

// RefSep is the canonical separator between family, scope, and ID components.
const RefSep = ":"

// RefScope is a typed ref scope identifier.
type RefScope string

// RefStatus is a typed ref status value.
type RefStatus string

// Ref family identifiers (untyped — used as plain strings in MakeRef).
const (
	RefFamilyVK = "VK" // secret refs
	RefFamilyVE = "VE" // config/env refs
)

// Ref scope identifiers.
const (
	RefScopeLocal    RefScope = "LOCAL"
	RefScopeTemp     RefScope = "TEMP"
	RefScopeExternal RefScope = "EXTERNAL"
)

// Ref status values.
const (
	RefStatusActive  RefStatus = "active"
	RefStatusTemp    RefStatus = "temp"
	RefStatusArchive RefStatus = "archive"
	RefStatusBlock   RefStatus = "block"
	RefStatusRevoke  RefStatus = "revoke"
)

// MakeRef constructs a canonical ref string: "FAMILY:SCOPE:ID".
func MakeRef(family string, scope RefScope, id string) string {
	return family + RefSep + string(scope) + RefSep + id
}

// ParseRef parses a canonical ref string into its components.
func ParseRef(raw string) (family string, scope RefScope, id string, err error) {
	parts := splitRef(raw)
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("invalid ref %q: must be FAMILY:SCOPE:ID", raw)
	}
	return parts[0], RefScope(parts[1]), parts[2], nil
}

func splitRef(s string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			parts = append(parts, s[start:i])
			start = i + 1
			if len(parts) == 2 {
				parts = append(parts, s[start:])
				return parts
			}
		}
	}
	if start < len(s) {
		parts = append(parts, s[start:])
	}
	return parts
}
