package dbutil

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"

	_ "github.com/mattn/go-sqlite3" // replaced by go-sqlcipher/v4 via go.mod replace directive
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// OpenGORM opens a SQLite/SQLCipher database via GORM.
// Reads VEILKEY_DB_KEY from env for optional SQLCipher encryption.
// Returns the GORM connection; caller is responsible for migration.
func OpenGORM(dbPath string) (*gorm.DB, error) {
	dsn := dbPath + "?_journal_mode=wal&_busy_timeout=5000"

	if key := os.Getenv("VEILKEY_DB_KEY"); key != "" {
		dsn += "&_pragma_key=" + url.QueryEscape(key)
	}

	sqlDB, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}

	if os.Getenv("VEILKEY_DB_KEY") != "" {
		version, verErr := SQLCipherVersion(sqlDB)
		if verErr != nil {
			_ = sqlDB.Close()
			return nil, fmt.Errorf("sqlcipher 지원 확인 실패: %w", verErr)
		}
		if version == "" {
			_ = sqlDB.Close()
			return nil, fmt.Errorf("VEILKEY_DB_KEY가 설정되었으나 바이너리가 SQLCipher 없이 빌드됨")
		}
		if _, verErr = sqlDB.Exec("SELECT count(*) FROM sqlite_master"); verErr != nil {
			_ = sqlDB.Close()
			return nil, fmt.Errorf("sqlcipher DB 키 검증 실패: %w", verErr)
		}
	}

	conn, err := gorm.Open(sqlite.Dialector{Conn: sqlDB}, &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		_ = sqlDB.Close()
		return nil, err
	}

	return conn, nil
}

// SQLCipherVersion checks if the underlying driver supports SQLCipher.
func SQLCipherVersion(conn *sql.DB) (string, error) {
	var version sql.NullString
	err := conn.QueryRow("PRAGMA cipher_version").Scan(&version)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return version.String, nil
}
