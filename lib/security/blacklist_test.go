package security

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func newTestRepository(t *testing.T) (*Repository, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "conf", "blacklist.db")
	repository, err := NewBlacklistRepository(dbPath)
	if err != nil {
		t.Fatalf("NewBlacklistRepository() error = %v", err)
	}
	t.Cleanup(func() {
		if err := repository.Close(); err != nil {
			t.Errorf("close test repository: %v", err)
		}
	})
	return repository, dbPath
}

func TestBlacklistRepositoryInitializesIdempotently(t *testing.T) {
	repository, dbPath := newTestRepository(t)
	if repository.Path() != dbPath {
		t.Fatalf("Path() = %q, want %q", repository.Path(), dbPath)
	}

	var journalMode, synchronous, busyTimeout string
	if err := repository.db.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatalf("read journal mode: %v", err)
	}
	if err := repository.db.QueryRow("PRAGMA synchronous").Scan(&synchronous); err != nil {
		t.Fatalf("read synchronous mode: %v", err)
	}
	if err := repository.db.QueryRow("PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
		t.Fatalf("read busy timeout: %v", err)
	}
	if journalMode != "wal" {
		t.Fatalf("journal_mode = %q, want wal", journalMode)
	}
	if synchronous != "1" {
		t.Fatalf("synchronous = %q, want 1 (NORMAL)", synchronous)
	}
	if busyTimeout != "5000" {
		t.Fatalf("busy_timeout = %q, want 5000", busyTimeout)
	}
	var schemaVersion int64
	if err := repository.db.QueryRow("PRAGMA user_version").Scan(&schemaVersion); err != nil {
		t.Fatalf("read schema version: %v", err)
	}
	if schemaVersion != currentSchemaVersion {
		t.Fatalf("user_version = %d, want %d", schemaVersion, currentSchemaVersion)
	}

	var tableCount, metadataTableCount, indexCount int
	if err := repository.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'blacklist_ip'").Scan(&tableCount); err != nil {
		t.Fatalf("check blacklist table: %v", err)
	}
	if err := repository.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'blacklist_meta'").Scan(&metadataTableCount); err != nil {
		t.Fatalf("check blacklist metadata table: %v", err)
	}
	if err := repository.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name IN ('uk_blacklist_ip', 'idx_blacklist_source', 'idx_blacklist_expire_at', 'idx_blacklist_created_at')").Scan(&indexCount); err != nil {
		t.Fatalf("check blacklist indexes: %v", err)
	}
	if tableCount != 1 || metadataTableCount != 1 || indexCount != 4 {
		t.Fatalf("schema objects = blacklist table %d, metadata table %d, indexes %d; want 1, 1, 4", tableCount, metadataTableCount, indexCount)
	}
	var createdAtIndexSQL string
	if err := repository.db.QueryRow("SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_blacklist_created_at'").Scan(&createdAtIndexSQL); err != nil {
		t.Fatalf("read created-at index: %v", err)
	}
	if !strings.Contains(createdAtIndexSQL, "created_at DESC, id DESC") {
		t.Fatalf("created-at index SQL = %q, want created_at/id ordering", createdAtIndexSQL)
	}

	if err := repository.Add(BlacklistIPInput{IP: "192.0.2.200", Reason: "survives restart"}); err != nil {
		t.Fatalf("Add() before restart error = %v", err)
	}
	if err := repository.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	reopened, err := NewBlacklistRepository(dbPath)
	if err != nil {
		t.Fatalf("reopen initialized database: %v", err)
	}
	if err := reopened.db.QueryRow("PRAGMA user_version").Scan(&schemaVersion); err != nil {
		t.Fatalf("read schema version after restart: %v", err)
	}
	if schemaVersion != currentSchemaVersion {
		t.Fatalf("user_version after restart = %d, want %d", schemaVersion, currentSchemaVersion)
	}
	if _, err := reopened.GetByIP("192.0.2.200"); err != nil {
		t.Fatalf("data after restart: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

func TestBlacklistRepositoryMigratesVersionZeroWithoutLosingData(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "blacklist.db")
	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open version zero database: %v", err)
	}
	rawDB.SetMaxOpenConns(1)
	oldSchema := `
CREATE TABLE blacklist_ip (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'manual',
    reason TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    first_seen_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    expire_at INTEGER DEFAULT NULL,
    hit_count INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX uk_blacklist_ip ON blacklist_ip(ip);
CREATE INDEX idx_blacklist_source ON blacklist_ip(source);
CREATE INDEX idx_blacklist_expire_at ON blacklist_ip(expire_at);
CREATE INDEX idx_blacklist_created_at ON blacklist_ip(created_at DESC);
INSERT INTO blacklist_ip (ip, first_seen_at, last_seen_at, created_at, updated_at)
VALUES ('192.0.2.240', 1, 1, 1, 1);
`
	if _, err := rawDB.Exec(oldSchema); err != nil {
		_ = rawDB.Close()
		t.Fatalf("create version zero database: %v", err)
	}
	if err := rawDB.Close(); err != nil {
		t.Fatalf("close version zero database: %v", err)
	}

	repository, err := NewBlacklistRepository(dbPath)
	if err != nil {
		t.Fatalf("migrate version zero database: %v", err)
	}
	defer repository.Close()
	var version int64
	if err := repository.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatalf("read migrated version: %v", err)
	}
	if version != currentSchemaVersion {
		t.Fatalf("migrated user_version = %d, want %d", version, currentSchemaVersion)
	}
	if _, err := repository.GetByIP("192.0.2.240"); err != nil {
		t.Fatalf("migrated record not preserved: %v", err)
	}
	var indexSQL string
	if err := repository.db.QueryRow("SELECT sql FROM sqlite_master WHERE name = 'idx_blacklist_created_at'").Scan(&indexSQL); err != nil {
		t.Fatalf("read migrated index: %v", err)
	}
	if !strings.Contains(indexSQL, "created_at DESC, id DESC") {
		t.Fatalf("migrated index SQL = %q, want created_at/id ordering", indexSQL)
	}
}

func TestBlacklistRepositoryMigratesVersionOneToVersionTwoWithoutLosingData(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "blacklist.db")
	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open version one database: %v", err)
	}
	rawDB.SetMaxOpenConns(1)
	if _, err := rawDB.Exec(schemaV1 + `
INSERT INTO blacklist_ip (ip, first_seen_at, last_seen_at, created_at, updated_at)
VALUES ('192.0.2.241', 1, 1, 1, 1);
PRAGMA user_version = 1;
`); err != nil {
		_ = rawDB.Close()
		t.Fatalf("create version one database: %v", err)
	}
	if err := rawDB.Close(); err != nil {
		t.Fatalf("close version one database: %v", err)
	}

	repository, err := NewBlacklistRepository(dbPath)
	if err != nil {
		t.Fatalf("migrate version one database: %v", err)
	}
	defer repository.Close()
	var version int64
	if err := repository.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatalf("read migrated version: %v", err)
	}
	if version != 2 {
		t.Fatalf("migrated user_version = %d, want 2", version)
	}
	if _, err := repository.GetByIP("192.0.2.241"); err != nil {
		t.Fatalf("migrated record not preserved: %v", err)
	}
	var metadataTableCount int
	if err := repository.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'blacklist_meta'").Scan(&metadataTableCount); err != nil {
		t.Fatalf("check metadata table: %v", err)
	}
	if metadataTableCount != 1 {
		t.Fatalf("metadata table count = %d, want 1", metadataTableCount)
	}
}

func TestBlacklistRepositoryCRUDAndMetadata(t *testing.T) {
	repository, _ := newTestRepository(t)
	expireAt := int64(1_800_000_000)
	entry := BlacklistIPInput{
		IP:          " 192.0.2.10:54321 ",
		Source:      "manual",
		Reason:      "test reason",
		ExpireAt:    &expireAt,
		FirstSeenAt: 1_700_000_000,
		LastSeenAt:  1_700_000_100,
		HitCount:    7,
		CreatedAt:   1_700_000_000,
		UpdatedAt:   1_700_000_100,
	}
	if err := repository.Add(entry); err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	got, err := repository.GetByIP("192.0.2.10")
	if err != nil {
		t.Fatalf("GetByIP() error = %v", err)
	}
	if got.IP != "192.0.2.10" || !got.Enabled || got.Source != entry.Source || got.Reason != entry.Reason {
		t.Fatalf("GetByIP() = %+v, want normalized enabled metadata", got)
	}
	if got.ExpireAt == nil || *got.ExpireAt != expireAt {
		t.Fatalf("ExpireAt = %v, want %d", got.ExpireAt, expireAt)
	}
	if got.HitCount != entry.HitCount || got.FirstSeenAt != entry.FirstSeenAt || got.LastSeenAt != entry.LastSeenAt {
		t.Fatalf("timestamps/hit count = %+v, want %+v", got, entry)
	}

	if err := repository.Add(entry); !errors.Is(err, ErrDuplicateIP) {
		t.Fatalf("duplicate Add() error = %v, want ErrDuplicateIP", err)
	}
	count, err := repository.Count()
	if err != nil || count != 1 {
		t.Fatalf("Count() = %d, %v; want 1, nil", count, err)
	}

	if err := repository.Disable("192.0.2.10:443"); err != nil {
		t.Fatalf("Disable() error = %v", err)
	}
	got, err = repository.GetByIP("192.0.2.10")
	if err != nil || got.Enabled {
		t.Fatalf("after Disable(), got = %+v, err = %v", got, err)
	}
	if err := repository.Enable("192.0.2.10"); err != nil {
		t.Fatalf("Enable() error = %v", err)
	}

	if err := repository.Delete("192.0.2.10"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := repository.GetByIP("192.0.2.10"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetByIP() after Delete error = %v, want ErrNotFound", err)
	}
	if err := repository.Delete("192.0.2.10"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second Delete() error = %v, want ErrNotFound", err)
	}
}

func TestBlacklistRepositoryListAndPageUseDatabasePagination(t *testing.T) {
	repository, _ := newTestRepository(t)
	entries := []BlacklistIP{
		{IP: "192.0.2.1", Source: "manual", Reason: "one", Enabled: true, CreatedAt: 1},
		{IP: "192.0.2.2", Source: "auto", Reason: "two", Enabled: true, CreatedAt: 2},
		{IP: "192.0.2.3", Source: "manual", Reason: "three", Enabled: true, CreatedAt: 3},
	}
	if err := repository.BulkInsert(entries); err != nil {
		t.Fatalf("BulkInsert() error = %v", err)
	}

	page, err := repository.Page(1, 2)
	if err != nil {
		t.Fatalf("Page(1, 2) error = %v", err)
	}
	if page.Total != 3 || len(page.Items) != 2 || page.Items[0].IP != "192.0.2.3" || page.Items[1].IP != "192.0.2.2" {
		t.Fatalf("Page(1, 2) = %+v, want newest two of three", page)
	}

	page, err = repository.Page(2, 2)
	if err != nil {
		t.Fatalf("Page(2, 2) error = %v", err)
	}
	if page.Total != 3 || len(page.Items) != 1 || page.Items[0].IP != "192.0.2.1" {
		t.Fatalf("Page(2, 2) = %+v, want oldest item", page)
	}

	enabled := true
	filtered, err := repository.ListWithOptions(ListOptions{Offset: 0, Limit: 10, Source: "manual", Enabled: &enabled})
	if err != nil {
		t.Fatalf("ListWithOptions() error = %v", err)
	}
	if len(filtered) != 2 || filtered[0].Source != "manual" || filtered[1].Source != "manual" {
		t.Fatalf("filtered ListWithOptions() = %+v, want two manual entries", filtered)
	}
}

func TestBlacklistRepositoryBulkInsertSkipsDuplicatesInOneBatch(t *testing.T) {
	repository, _ := newTestRepository(t)
	entries := []BlacklistIP{
		{IP: "192.0.2.10", Enabled: true},
		{IP: " 192.0.2.10:443 ", Enabled: true},
		{IP: "[2001:db8::10]:443", Source: "manual", Reason: "ipv6", Enabled: true},
		{IP: "2001:0db8:0:0:0:0:0:10", Source: "auto", Enabled: true},
	}
	if err := repository.BulkInsert(entries); err != nil {
		t.Fatalf("BulkInsert() error = %v", err)
	}
	count, err := repository.Count()
	if err != nil || count != 2 {
		t.Fatalf("Count() after BulkInsert = %d, %v; want 2, nil", count, err)
	}

	got, err := repository.GetByIP("[2001:db8::10]:8443")
	if err != nil {
		t.Fatalf("GetByIP() IPv6 error = %v", err)
	}
	if got.IP != "2001:db8::10" || got.Source != "manual" || got.Reason != "ipv6" {
		t.Fatalf("IPv6 record = %+v, want first duplicate's metadata", got)
	}
}

func TestNormalizeIP(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "ipv4", input: " 192.0.2.10 ", want: "192.0.2.10"},
		{name: "ipv4 with port", input: "192.0.2.10:54321", want: "192.0.2.10"},
		{name: "ipv6", input: "2001:0db8:0:0:0:0:0:10", want: "2001:db8::10"},
		{name: "ipv6 with port", input: "[2001:db8::10]:54321", want: "2001:db8::10"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeIP(tt.input)
			if err != nil || got != tt.want {
				t.Fatalf("NormalizeIP(%q) = %q, %v; want %q, nil", tt.input, got, err, tt.want)
			}
		})
	}

	for _, input := range []string{"", "not-an-ip", "192.0.2.10:bad", "999.999.999.999", "[2001:db8::10"} {
		t.Run("invalid "+input, func(t *testing.T) {
			if _, err := NormalizeIP(input); !errors.Is(err, ErrInvalidIP) {
				t.Fatalf("NormalizeIP(%q) error = %v, want ErrInvalidIP", input, err)
			}
		})
	}
}

func TestBlacklistRepositoryPersistsAfterCloseAndReopen(t *testing.T) {
	repository, dbPath := newTestRepository(t)
	if err := repository.Add(BlacklistIPInput{IP: "203.0.113.7", Source: "manual", Reason: "persist"}); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	if err := repository.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	reopened, err := NewBlacklistRepository(dbPath)
	if err != nil {
		t.Fatalf("reopen repository: %v", err)
	}
	defer reopened.Close()
	got, err := reopened.GetByIP("203.0.113.7")
	if err != nil {
		t.Fatalf("GetByIP() after reopen error = %v", err)
	}
	if got.Reason != "persist" || got.Source != "manual" {
		t.Fatalf("reopened record = %+v, want persisted metadata", got)
	}
}

func TestBlacklistRepositoryRejectsInvalidBulkInputWithoutPartialInsert(t *testing.T) {
	repository, _ := newTestRepository(t)
	err := repository.BulkInsert([]BlacklistIP{{IP: "192.0.2.30", Enabled: true}, {IP: "invalid", Enabled: true}})
	if !errors.Is(err, ErrInvalidIP) {
		t.Fatalf("BulkInsert() error = %v, want ErrInvalidIP", err)
	}
	count, countErr := repository.Count()
	if countErr != nil || count != 0 {
		t.Fatalf("Count() after rejected bulk = %d, %v; want 0, nil", count, countErr)
	}
}

func TestBlacklistRepositoryBulkInsertPreservesDisabledState(t *testing.T) {
	repository, _ := newTestRepository(t)
	if err := repository.BulkInsert([]BlacklistIP{{IP: "198.51.100.20", Enabled: false}}); err != nil {
		t.Fatalf("BulkInsert() error = %v", err)
	}

	got, err := repository.GetByIP("198.51.100.20")
	if err != nil {
		t.Fatalf("GetByIP() after disabled bulk insert error = %v", err)
	}
	if got.Enabled {
		t.Fatalf("BulkInsert() enabled = true, want disabled record")
	}
	if err := repository.Enable("198.51.100.20"); err != nil {
		t.Fatalf("Enable() error = %v", err)
	}
	got, err = repository.GetByIP("198.51.100.20")
	if err != nil || !got.Enabled {
		t.Fatalf("after Enable(), got = %+v, err = %v; want enabled", got, err)
	}
	if err := repository.Disable("198.51.100.20"); err != nil {
		t.Fatalf("Disable() error = %v", err)
	}
	got, err = repository.GetByIP("198.51.100.20")
	if err != nil || got.Enabled {
		t.Fatalf("after Disable(), got = %+v, err = %v; want disabled", got, err)
	}
}

func TestBlacklistRepositoryAddDefaultsEnabledButAcceptsExplicitDisabled(t *testing.T) {
	repository, _ := newTestRepository(t)
	if err := repository.Add(BlacklistIPInput{IP: "198.51.100.21"}); err != nil {
		t.Fatalf("default Add() error = %v", err)
	}
	defaultEntry, err := repository.GetByIP("198.51.100.21")
	if err != nil || !defaultEntry.Enabled {
		t.Fatalf("default Add() entry = %+v, err = %v; want enabled", defaultEntry, err)
	}

	disabled := false
	if err := repository.Add(BlacklistIPInput{IP: "198.51.100.22", Enabled: &disabled}); err != nil {
		t.Fatalf("explicit disabled Add() error = %v", err)
	}
	explicitEntry, err := repository.GetByIP("198.51.100.22")
	if err != nil || explicitEntry.Enabled {
		t.Fatalf("explicit disabled Add() entry = %+v, err = %v; want disabled", explicitEntry, err)
	}
}

func TestBlacklistDBPath(t *testing.T) {
	if got, want := BlacklistDBPath("/var/lib/nps"), filepath.Join("/var/lib/nps", "conf", "blacklist.db"); got != want {
		t.Fatalf("BlacklistDBPath() = %q, want %q", got, want)
	}
}

func TestRepositoryCanBeOpenedByDatabaseSQLAfterClose(t *testing.T) {
	repository, dbPath := newTestRepository(t)
	if err := repository.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open() after repository close: %v", err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'blacklist_ip'").Scan(&count); err != nil {
		t.Fatalf("query reopened database: %v", err)
	}
	if count != 1 {
		t.Fatalf("reopened blacklist table count = %d, want 1", count)
	}
}
