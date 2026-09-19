// Package security contains persistence and security-related services.
package security

import (
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"ehang.io/nps/lib/common"
	_ "modernc.org/sqlite"
)

const (
	defaultBlacklistSource = "manual"
	defaultPageSize        = 50
	currentSchemaVersion   = 2
	legacyImportMarkerKey  = "legacy_global_blacklist_imported"
)

var (
	// ErrDuplicateIP is returned when Add attempts to insert an IP that is
	// already present in the blacklist.
	ErrDuplicateIP = errors.New("blacklist IP already exists")

	// ErrNotFound is returned when an operation targets an IP that is not in
	// the blacklist.
	ErrNotFound = errors.New("blacklist IP not found")

	// ErrInvalidIP is returned when an IP value cannot be parsed or contains a
	// port that is not valid.
	ErrInvalidIP = errors.New("invalid IP address")
)

// BlacklistIP is a persisted blacklist record. Timestamp fields are Unix
// seconds, matching the INTEGER representation used by SQLite.
type BlacklistIP struct {
	ID          int64
	IP          string
	Source      string
	Reason      string
	Enabled     bool
	FirstSeenAt int64
	LastSeenAt  int64
	ExpireAt    *int64
	HitCount    int64
	CreatedAt   int64
	UpdatedAt   int64
}

// BlacklistIPInput contains the fields accepted by Add. Enabled is a
// pointer so callers can distinguish an omitted state (default: enabled)
// from an explicit disabled state.
type BlacklistIPInput struct {
	IP          string
	Source      string
	Reason      string
	Enabled     *bool
	FirstSeenAt int64
	LastSeenAt  int64
	ExpireAt    *int64
	HitCount    int64
	CreatedAt   int64
	UpdatedAt   int64
}

// ListOptions controls filtered, SQLite-backed list queries. Offset and
// Limit are applied by SQLite; records are never paginated in memory.
type ListOptions struct {
	Offset  int
	Limit   int
	IP      string
	Source  string
	Enabled *bool
}

// PageResult is the result of a one-based page query.
type PageResult struct {
	Items    []BlacklistIP
	Total    int64
	Page     int
	PageSize int
}

// Repository owns the SQLite connection for blacklist persistence. A
// repository must be closed when it is no longer needed.
type Repository struct {
	db        *sql.DB
	dbPath    string
	closeOnce sync.Once
	closeErr  error
}

// schemaV1 is the immutable schema introduced by the version 0 -> 1
// migration. Once released, do not edit its historical meaning; future
// schema changes must be represented by explicit versioned migrations.
const schemaV1 = `
CREATE TABLE IF NOT EXISTS blacklist_ip (
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
CREATE UNIQUE INDEX IF NOT EXISTS uk_blacklist_ip
    ON blacklist_ip(ip);
CREATE INDEX IF NOT EXISTS idx_blacklist_source
    ON blacklist_ip(source);
CREATE INDEX IF NOT EXISTS idx_blacklist_expire_at
    ON blacklist_ip(expire_at);
CREATE INDEX IF NOT EXISTS idx_blacklist_created_at
    ON blacklist_ip(created_at DESC, id DESC);
`

// migrationV1ToV2SQL contains only the additions made by the version 1 -> 2
// migration. Keep schemaV1 unchanged; historical migrations are immutable.
const migrationV1ToV2SQL = `
CREATE TABLE IF NOT EXISTS blacklist_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
`

const activeBlacklistWhere = "enabled = 1 AND (expire_at IS NULL OR expire_at > ?)"

const (
	insertSQL = `
INSERT INTO blacklist_ip (
    ip, source, reason, enabled, first_seen_at, last_seen_at,
    expire_at, hit_count, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`

	selectColumns = `
id, ip, source, reason, enabled, first_seen_at, last_seen_at,
expire_at, hit_count, created_at, updated_at
`
)

// BlacklistDBPath returns the database location used for a given NPS run
// path. The directory is deliberately derived from runPath rather than the
// process working directory.
func BlacklistDBPath(runPath string) string {
	return filepath.Join(runPath, "conf", "blacklist.db")
}

// NewDefaultBlacklistRepository opens the blacklist database under the
// current NPS run path (conf/blacklist.db).
func NewDefaultBlacklistRepository() (*Repository, error) {
	return NewBlacklistRepository(BlacklistDBPath(common.GetRunPath()))
}

// NewRepository is the short constructor name for a blacklist repository.
func NewRepository(dbPath string) (*Repository, error) {
	return NewBlacklistRepository(dbPath)
}

// NewBlacklistRepository opens or creates a SQLite blacklist database,
// applies the required connection settings, and creates the schema and
// indexes. Any open or initialization error is returned to the caller.
func NewBlacklistRepository(dbPath string) (*Repository, error) {
	if strings.TrimSpace(dbPath) == "" {
		return nil, errors.New("blacklist database path is empty")
	}

	if dbPath != ":memory:" && !strings.HasPrefix(dbPath, "file:") {
		if err := os.MkdirAll(filepath.Dir(filepath.Clean(dbPath)), 0o755); err != nil {
			return nil, fmt.Errorf("create blacklist database directory: %w", err)
		}
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open blacklist database %q: %w", dbPath, err)
	}
	// SQLite is the blacklist persistence layer, not a general-purpose
	// connection pool. One connection also keeps the connection-scoped
	// PRAGMAs consistent and avoids unnecessary lock contention.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := initializeDatabase(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize blacklist database %q: %w", dbPath, err)
	}

	return &Repository{db: db, dbPath: dbPath}, nil
}

func initializeDatabase(db *sql.DB) error {
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA busy_timeout=5000",
	}
	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			return fmt.Errorf("%s: %w", pragma, err)
		}
	}
	return migrateDatabase(db)
}

func migrateDatabase(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin blacklist schema migration: %w", err)
	}

	var version int64
	if err := tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("read blacklist schema version: %w", err)
	}
	if version > currentSchemaVersion {
		_ = tx.Rollback()
		return fmt.Errorf("unsupported blacklist schema version %d (current version %d)", version, currentSchemaVersion)
	}

	for version < currentSchemaVersion {
		switch version {
		case 0:
			if err := migrateV0ToV1(tx); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("migrate blacklist schema 0 to 1: %w", err)
			}
			version = 1
		case 1:
			if err := migrateV1ToV2(tx); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("migrate blacklist schema 1 to 2: %w", err)
			}
			version = 2
		default:
			_ = tx.Rollback()
			return fmt.Errorf("no migration for blacklist schema version %d", version)
		}
		if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", version)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("set blacklist schema version %d: %w", version, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit blacklist schema migration: %w", err)
	}
	return nil
}

func migrateV0ToV1(tx *sql.Tx) error {
	if _, err := tx.Exec(schemaV1); err != nil {
		return fmt.Errorf("create schema v1: %w", err)
	}
	// Recreate this index so databases created by the previous repository
	// revision also receive the id tie-breaker.
	if _, err := tx.Exec("DROP INDEX IF EXISTS idx_blacklist_created_at"); err != nil {
		return fmt.Errorf("replace blacklist created-at index: %w", err)
	}
	if _, err := tx.Exec("CREATE INDEX idx_blacklist_created_at ON blacklist_ip(created_at DESC, id DESC)"); err != nil {
		return fmt.Errorf("create blacklist created-at index: %w", err)
	}
	return nil
}

func migrateV1ToV2(tx *sql.Tx) error {
	if _, err := tx.Exec(migrationV1ToV2SQL); err != nil {
		return fmt.Errorf("apply migration v1 to v2: %w", err)
	}
	return nil
}

// Path returns the filesystem path used by the repository.
func (r *Repository) Path() string {
	return r.dbPath
}

// Close closes the repository's long-lived database connection.
func (r *Repository) Close() error {
	if r == nil || r.db == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		r.closeErr = r.db.Close()
	})
	return r.closeErr
}

// Add inserts an IP. If input.Enabled is nil, the new record is enabled by
// default; a non-nil pointer preserves the caller's explicit state. IP
// values are normalized before they become the unique key.
func (r *Repository) Add(input BlacklistIPInput) error {
	normalized, err := prepareEntry(inputToEntry(input))
	if err != nil {
		return err
	}

	result, err := r.db.Exec(insertSQL+" ON CONFLICT(ip) DO NOTHING", entryArgs(normalized)...)
	if err != nil {
		return fmt.Errorf("add blacklist IP %q: %w", normalized.IP, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check added blacklist IP %q: %w", normalized.IP, err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: %s", ErrDuplicateIP, normalized.IP)
	}
	return nil
}

// GetByIP returns one record using the same normalization rules as Add.
func (r *Repository) GetByIP(ip string) (*BlacklistIP, error) {
	normalized, err := NormalizeIP(ip)
	if err != nil {
		return nil, err
	}

	row := r.db.QueryRow("SELECT "+selectColumns+" FROM blacklist_ip WHERE ip = ?", normalized)
	entry, err := scanBlacklistIP(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, normalized)
	}
	if err != nil {
		return nil, fmt.Errorf("get blacklist IP %q: %w", normalized, err)
	}
	return &entry, nil
}

// Delete removes a record by IP.
func (r *Repository) Delete(ip string) error {
	normalized, err := NormalizeIP(ip)
	if err != nil {
		return err
	}

	result, err := r.db.Exec("DELETE FROM blacklist_ip WHERE ip = ?", normalized)
	if err != nil {
		return fmt.Errorf("delete blacklist IP %q: %w", normalized, err)
	}
	return requireAffected(result, ErrNotFound, normalized)
}

// Enable marks a blacklist record as enabled.
func (r *Repository) Enable(ip string) error {
	return r.setEnabled(ip, true)
}

// Disable marks a blacklist record as disabled.
func (r *Repository) Disable(ip string) error {
	return r.setEnabled(ip, false)
}

func (r *Repository) setEnabled(ip string, enabled bool) error {
	normalized, err := NormalizeIP(ip)
	if err != nil {
		return err
	}

	result, err := r.db.Exec(
		"UPDATE blacklist_ip SET enabled = ?, updated_at = ? WHERE ip = ?",
		boolValue(enabled), time.Now().Unix(), normalized,
	)
	if err != nil {
		return fmt.Errorf("set blacklist IP %q enabled=%t: %w", normalized, enabled, err)
	}
	return requireAffected(result, ErrNotFound, normalized)
}

// Count returns the total number of persisted blacklist records.
func (r *Repository) Count() (int64, error) {
	var count int64
	if err := r.db.QueryRow("SELECT COUNT(*) FROM blacklist_ip").Scan(&count); err != nil {
		return 0, fmt.Errorf("count blacklist IPs: %w", err)
	}
	return count, nil
}

// List returns a page using offset/limit pagination performed by SQLite.
// Results are ordered newest-first, with ID as a deterministic tie-breaker.
func (r *Repository) List(offset, limit int) ([]BlacklistIP, error) {
	return r.ListWithOptions(ListOptions{Offset: offset, Limit: limit})
}

// ListWithOptions returns a filtered page using SQLite LIMIT/OFFSET. An IP
// filter is normalized before it is sent to SQLite.
func (r *Repository) ListWithOptions(options ListOptions) ([]BlacklistIP, error) {
	if options.Offset < 0 {
		return nil, errors.New("blacklist list offset must not be negative")
	}
	if options.Limit <= 0 {
		return nil, errors.New("blacklist list limit must be positive")
	}

	where := make([]string, 0, 3)
	args := make([]any, 0, 5)
	if options.IP != "" {
		ip, err := NormalizeIP(options.IP)
		if err != nil {
			return nil, err
		}
		where = append(where, "ip = ?")
		args = append(args, ip)
	}
	if options.Source != "" {
		where = append(where, "source = ?")
		args = append(args, options.Source)
	}
	if options.Enabled != nil {
		where = append(where, "enabled = ?")
		args = append(args, boolValue(*options.Enabled))
	}

	query := "SELECT " + selectColumns + " FROM blacklist_ip"
	if len(where) != 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
	args = append(args, options.Limit, options.Offset)

	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list blacklist IPs: %w", err)
	}
	defer rows.Close()

	entries := make([]BlacklistIP, 0, options.Limit)
	for rows.Next() {
		entry, err := scanBlacklistIP(rows)
		if err != nil {
			return nil, fmt.Errorf("scan blacklist IP: %w", err)
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate blacklist IPs: %w", err)
	}
	return entries, nil
}

// Page returns a one-based page and its total row count. Both the page and
// count are computed by SQLite; no full table is loaded into Go.
func (r *Repository) Page(page, pageSize int) (PageResult, error) {
	if page <= 0 {
		return PageResult{}, errors.New("blacklist page must be positive")
	}
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	if page > math.MaxInt/pageSize {
		return PageResult{}, errors.New("blacklist page offset overflows int")
	}

	items, err := r.List((page-1)*pageSize, pageSize)
	if err != nil {
		return PageResult{}, err
	}
	total, err := r.Count()
	if err != nil {
		return PageResult{}, err
	}
	return PageResult{Items: items, Total: total, Page: page, PageSize: pageSize}, nil
}

// BulkInsert inserts all entries in one transaction using one prepared
// statement. Each entry is normalized immediately before its Exec, so the
// repository does not allocate an input-sized copy. Duplicate normalized IPs
// are skipped so a duplicate cannot abort a large historical import. Each
// entry's Enabled value is preserved; other database errors and invalid IPs
// abort the entire transaction.
func (r *Repository) BulkInsert(entries []BlacklistIP) error {
	if len(entries) == 0 {
		return nil
	}

	tx, err := r.db.Begin()
	if err != nil {
		return fmt.Errorf("begin blacklist bulk insert: %w", err)
	}
	stmt, err := tx.Prepare(insertSQL + " ON CONFLICT(ip) DO NOTHING")
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("prepare blacklist bulk insert: %w", err)
	}
	for i, entry := range entries {
		normalized, err := prepareEntry(entry)
		if err != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
			return fmt.Errorf("prepare blacklist IP at index %d: %w", i, err)
		}
		if _, err := stmt.Exec(entryArgs(normalized)...); err != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
			return fmt.Errorf("bulk insert blacklist IP %q: %w", normalized.IP, err)
		}
	}
	if err := stmt.Close(); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("close blacklist bulk insert statement: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit blacklist bulk insert: %w", err)
	}
	return nil
}

// WalkActiveIndex streams only the fields needed by the runtime index. The
// callback is invoked once per row and records are not accumulated in a Go
// slice, which keeps startup memory bounded for large blacklists.
func (r *Repository) WalkActiveIndex(now int64, fn func(ip string, expireAt *int64) error) error {
	if fn == nil {
		return errors.New("blacklist active-row callback is nil")
	}
	rows, err := r.db.Query(
		"SELECT ip, expire_at FROM blacklist_ip WHERE "+activeBlacklistWhere,
		now,
	)
	if err != nil {
		return fmt.Errorf("walk active blacklist IPs: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var ip string
		var expireAt sql.NullInt64
		if err := rows.Scan(&ip, &expireAt); err != nil {
			return fmt.Errorf("scan active blacklist index row: %w", err)
		}
		var expiry *int64
		if expireAt.Valid {
			expiryValue := expireAt.Int64
			expiry = &expiryValue
		}
		if err := fn(ip, expiry); err != nil {
			return fmt.Errorf("process active blacklist IP %q: %w", ip, err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate active blacklist index rows: %w", err)
	}
	return nil
}

// CountActive returns the number of records that WalkActiveIndex would stream.
func (r *Repository) CountActive(now int64) (int64, error) {
	var count int64
	if err := r.db.QueryRow(
		"SELECT COUNT(*) FROM blacklist_ip WHERE "+activeBlacklistWhere,
		now,
	).Scan(&count); err != nil {
		return 0, fmt.Errorf("count active blacklist IPs: %w", err)
	}
	return count, nil
}

// LegacyImportStats describes one atomic legacy global blacklist import.
type LegacyImportStats struct {
	Total           int
	Imported        int
	Duplicates      int
	Invalid         int
	SkippedByMarker bool
	InvalidSamples  []string
}

// ImportLegacyOnce imports legacy global.json IPs exactly once. The marker,
// valid inserts, duplicate handling, and empty-input case share one
// transaction. Existing rows retain their metadata because inserts use
// ON CONFLICT DO NOTHING.
func (r *Repository) ImportLegacyOnce(rawIPs []string) (LegacyImportStats, error) {
	stats := LegacyImportStats{Total: len(rawIPs)}
	tx, err := r.db.Begin()
	if err != nil {
		return stats, fmt.Errorf("begin legacy blacklist import: %w", err)
	}

	var marker string
	err = tx.QueryRow("SELECT value FROM blacklist_meta WHERE key = ?", legacyImportMarkerKey).Scan(&marker)
	if err == nil {
		stats.SkippedByMarker = true
		if err := tx.Commit(); err != nil {
			return stats, fmt.Errorf("commit skipped legacy blacklist import: %w", err)
		}
		return stats, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		_ = tx.Rollback()
		return stats, fmt.Errorf("check legacy blacklist import marker: %w", err)
	}

	stmt, err := tx.Prepare(insertSQL + " ON CONFLICT(ip) DO NOTHING")
	if err != nil {
		_ = tx.Rollback()
		return stats, fmt.Errorf("prepare legacy blacklist import: %w", err)
	}
	now := time.Now().Unix()
	for _, rawIP := range rawIPs {
		addr, err := ParseIPAddr(rawIP)
		if err != nil {
			stats.Invalid++
			if len(stats.InvalidSamples) < 10 {
				stats.InvalidSamples = append(stats.InvalidSamples, strings.TrimSpace(rawIP))
			}
			continue
		}
		entry := BlacklistIP{
			IP:          addr.String(),
			Source:      "import",
			Enabled:     true,
			FirstSeenAt: now,
			LastSeenAt:  now,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		result, err := stmt.Exec(entryArgs(entry)...)
		if err != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
			return stats, fmt.Errorf("import legacy blacklist IP %q: %w", entry.IP, err)
		}
		rows, err := result.RowsAffected()
		if err != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
			return stats, fmt.Errorf("count imported legacy blacklist IP %q: %w", entry.IP, err)
		}
		if rows == 0 {
			stats.Duplicates++
		} else {
			stats.Imported++
		}
	}
	if err := stmt.Close(); err != nil {
		_ = tx.Rollback()
		return stats, fmt.Errorf("close legacy blacklist import statement: %w", err)
	}
	if _, err := tx.Exec(
		"INSERT INTO blacklist_meta(key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO NOTHING",
		legacyImportMarkerKey, "1", now,
	); err != nil {
		_ = tx.Rollback()
		return stats, fmt.Errorf("write legacy blacklist import marker: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return stats, fmt.Errorf("commit legacy blacklist import: %w", err)
	}
	return stats, nil
}

// GetMeta reads a metadata value. The boolean is false when the key is
// absent, without treating absence as a database error.
func (r *Repository) GetMeta(key string) (string, bool, error) {
	var value string
	err := r.db.QueryRow("SELECT value FROM blacklist_meta WHERE key = ?", key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("get blacklist metadata %q: %w", key, err)
	}
	return value, true, nil
}

// SetMeta writes a metadata value for administrative and migration tooling.
func (r *Repository) SetMeta(key, value string) error {
	if strings.TrimSpace(key) == "" {
		return errors.New("blacklist metadata key is empty")
	}
	if _, err := r.db.Exec(
		"INSERT INTO blacklist_meta(key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
		key, value, time.Now().Unix(),
	); err != nil {
		return fmt.Errorf("set blacklist metadata %q: %w", key, err)
	}
	return nil
}

// ParseIPAddr trims and canonicalizes a bare IP or an IP with a port. Ports
// are accepted only as input and never become part of the persisted key.
func ParseIPAddr(raw string) (netip.Addr, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return netip.Addr{}, fmt.Errorf("%w: empty value", ErrInvalidIP)
	}
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		value = value[1 : len(value)-1]
	}

	if addr, err := netip.ParseAddr(value); err == nil {
		return canonicalAddr(addr), nil
	}
	if addrPort, err := netip.ParseAddrPort(value); err == nil {
		return canonicalAddr(addrPort.Addr()), nil
	}
	return netip.Addr{}, fmt.Errorf("%w: %q", ErrInvalidIP, raw)
}

// NormalizeIP returns the canonical string form used as the SQLite key.
func NormalizeIP(raw string) (string, error) {
	addr, err := ParseIPAddr(raw)
	if err != nil {
		return "", err
	}
	return addr.String(), nil
}

func canonicalAddr(addr netip.Addr) netip.Addr {
	return addr.Unmap().WithZone("")
}

func inputToEntry(input BlacklistIPInput) BlacklistIP {
	enabled := true
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	return BlacklistIP{
		IP:          input.IP,
		Source:      input.Source,
		Reason:      input.Reason,
		Enabled:     enabled,
		FirstSeenAt: input.FirstSeenAt,
		LastSeenAt:  input.LastSeenAt,
		ExpireAt:    input.ExpireAt,
		HitCount:    input.HitCount,
		CreatedAt:   input.CreatedAt,
		UpdatedAt:   input.UpdatedAt,
	}
}

func prepareEntry(entry BlacklistIP) (BlacklistIP, error) {
	normalized, err := NormalizeIP(entry.IP)
	if err != nil {
		return BlacklistIP{}, err
	}
	entry.IP = normalized
	entry.Source = strings.TrimSpace(entry.Source)
	if entry.Source == "" {
		entry.Source = defaultBlacklistSource
	}
	now := time.Now().Unix()
	if entry.FirstSeenAt == 0 {
		entry.FirstSeenAt = now
	}
	if entry.LastSeenAt == 0 {
		entry.LastSeenAt = entry.FirstSeenAt
	}
	if entry.CreatedAt == 0 {
		entry.CreatedAt = now
	}
	if entry.UpdatedAt == 0 {
		entry.UpdatedAt = now
	}
	return entry, nil
}

func entryArgs(entry BlacklistIP) []any {
	return []any{
		entry.IP,
		entry.Source,
		entry.Reason,
		boolValue(entry.Enabled),
		entry.FirstSeenAt,
		entry.LastSeenAt,
		entry.ExpireAt,
		entry.HitCount,
		entry.CreatedAt,
		entry.UpdatedAt,
	}
}

func boolValue(value bool) int {
	if value {
		return 1
	}
	return 0
}

type scanner interface {
	Scan(dest ...any) error
}

func scanBlacklistIP(row scanner) (BlacklistIP, error) {
	var (
		entry    BlacklistIP
		enabled  int
		expireAt sql.NullInt64
	)
	if err := row.Scan(
		&entry.ID,
		&entry.IP,
		&entry.Source,
		&entry.Reason,
		&enabled,
		&entry.FirstSeenAt,
		&entry.LastSeenAt,
		&expireAt,
		&entry.HitCount,
		&entry.CreatedAt,
		&entry.UpdatedAt,
	); err != nil {
		return BlacklistIP{}, err
	}
	entry.Enabled = enabled != 0
	if expireAt.Valid {
		entry.ExpireAt = &expireAt.Int64
	}
	return entry, nil
}

func requireAffected(result sql.Result, notFound error, ip string) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check blacklist IP %q update: %w", ip, err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: %s", notFound, ip)
	}
	return nil
}
