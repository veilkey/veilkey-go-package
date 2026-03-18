package refs

import "fmt"

// Scan implements sql.Scanner so database/sql and GORM can scan
// string columns directly into RefScope.
func (s *RefScope) Scan(src any) error {
	str, ok := src.(string)
	if !ok {
		return fmt.Errorf("RefScope: expected string, got %T", src)
	}
	*s = RefScope(str)
	return nil
}

// Scan implements sql.Scanner so database/sql and GORM can scan
// string columns directly into RefStatus.
func (s *RefStatus) Scan(src any) error {
	str, ok := src.(string)
	if !ok {
		return fmt.Errorf("RefStatus: expected string, got %T", src)
	}
	*s = RefStatus(str)
	return nil
}
