package security

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func newTestBlacklistService(t *testing.T) (*BlacklistService, *Repository) {
	t.Helper()
	repository, _ := newTestRepository(t)
	service, _, err := NewBlacklistService(repository, nil)
	if err != nil {
		t.Fatalf("NewBlacklistService() error = %v", err)
	}
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Errorf("close blacklist service: %v", err)
		}
	})
	return service, repository
}

func TestBlacklistServiceLoadsOnlyActiveCanonicalRecords(t *testing.T) {
	repository, _ := newTestRepository(t)
	now := time.Now().Unix()
	disabled := false
	expired := now - 1
	future := now + 2
	for _, entry := range []BlacklistIPInput{
		{IP: "192.0.2.1", LastSeenAt: 123, HitCount: 7},
		{IP: "[2001:db8::1]:443"},
		{IP: "::ffff:192.0.2.3"},
		{IP: "192.0.2.4", Enabled: &disabled},
		{IP: "192.0.2.5", ExpireAt: &expired},
		{IP: "192.0.2.6", ExpireAt: &future},
	} {
		if err := repository.Add(entry); err != nil {
			t.Fatalf("seed blacklist record %q: %v", entry.IP, err)
		}
	}

	service, _, err := NewBlacklistService(repository, nil)
	if err != nil {
		t.Fatalf("NewBlacklistService() error = %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })

	for _, rawIP := range []string{"192.0.2.1", "192.0.2.1:443", "[2001:db8::1]:8443", "192.0.2.3", "192.0.2.6"} {
		if !service.Contains(rawIP) {
			t.Errorf("Contains(%q) = false, want true", rawIP)
		}
	}
	for _, rawIP := range []string{"192.0.2.4", "192.0.2.5", "192.0.2.7", "not-an-ip"} {
		if service.Contains(rawIP) {
			t.Errorf("Contains(%q) = true, want false", rawIP)
		}
	}
	before, err := repository.GetByIP("192.0.2.1")
	if err != nil {
		t.Fatalf("read record before Contains() check: %v", err)
	}
	for i := 0; i < 10; i++ {
		_ = service.Contains("192.0.2.1:443")
	}
	after, err := repository.GetByIP("192.0.2.1")
	if err != nil {
		t.Fatalf("read record after Contains() check: %v", err)
	}
	if after.LastSeenAt != before.LastSeenAt || after.HitCount != before.HitCount {
		t.Fatalf("Contains() changed persisted counters: before=%+v after=%+v", before, after)
	}

	time.Sleep(2200 * time.Millisecond)
	if service.Contains("192.0.2.6") {
		t.Fatal("Contains(future expiry) = true after expiry, want false")
	}
}

func TestBlacklistServicePreservesDisabledStateAndPublishesEnableDisable(t *testing.T) {
	service, repository := newTestBlacklistService(t)

	if err := repository.BulkInsert([]BlacklistIP{{IP: "198.51.100.20", Enabled: false}}); err != nil {
		t.Fatalf("BulkInsert() error = %v", err)
	}
	if err := service.Reload(); err != nil {
		t.Fatalf("Reload() after disabled bulk insert error = %v", err)
	}
	if service.Contains("198.51.100.20") {
		t.Fatal("disabled BulkInsert record is present in runtime index")
	}
	got, err := repository.GetByIP("198.51.100.20")
	if err != nil || got.Enabled {
		t.Fatalf("BulkInsert record = %+v, err = %v; want disabled", got, err)
	}

	if err := service.Enable("198.51.100.20"); err != nil {
		t.Fatalf("service Enable() error = %v", err)
	}
	if !service.Contains("198.51.100.20") {
		t.Fatal("enabled record is missing from runtime index")
	}
	if err := service.Disable("198.51.100.20"); err != nil {
		t.Fatalf("service Disable() error = %v", err)
	}
	if service.Contains("198.51.100.20") {
		t.Fatal("disabled record remains in runtime index")
	}
}

func TestBlacklistServiceMutationsPublishAfterPersistence(t *testing.T) {
	service, repository := newTestBlacklistService(t)
	if err := service.Add(BlacklistIPInput{IP: "203.0.113.10"}); err != nil {
		t.Fatalf("service Add() error = %v", err)
	}
	if !service.Contains("203.0.113.10") {
		t.Fatal("added active record is missing from runtime index")
	}

	disabled := false
	if err := service.Add(BlacklistIPInput{IP: "203.0.113.11", Enabled: &disabled}); err != nil {
		t.Fatalf("service Add(disabled) error = %v", err)
	}
	if service.Contains("203.0.113.11") {
		t.Fatal("explicitly disabled record was published")
	}
	expired := time.Now().Unix() - 1
	if err := service.Add(BlacklistIPInput{IP: "203.0.113.12", ExpireAt: &expired}); err != nil {
		t.Fatalf("service Add(expired) error = %v", err)
	}
	if service.Contains("203.0.113.12") {
		t.Fatal("expired record was published")
	}

	if err := service.Delete("203.0.113.10:443"); err != nil {
		t.Fatalf("service Delete() error = %v", err)
	}
	if service.Contains("203.0.113.10") {
		t.Fatal("deleted record remains in runtime index")
	}
	if _, err := repository.GetByIP("203.0.113.10"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted record lookup error = %v, want ErrNotFound", err)
	}
}

func TestBlacklistServiceReloadIsAtomicAndDBFailuresDoNotDirtyIndex(t *testing.T) {
	service, repository := newTestBlacklistService(t)
	if err := service.Add(BlacklistIPInput{IP: "192.0.2.30"}); err != nil {
		t.Fatalf("seed service record: %v", err)
	}
	if err := repository.Add(BlacklistIPInput{IP: "192.0.2.31"}); err != nil {
		t.Fatalf("seed reload record: %v", err)
	}
	if err := repository.Delete("192.0.2.30"); err != nil {
		t.Fatalf("remove old reload record: %v", err)
	}
	if err := service.Reload(); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if service.Contains("192.0.2.30") || !service.Contains("192.0.2.31") {
		t.Fatal("Reload() did not atomically publish the current database contents")
	}

	if err := repository.Close(); err != nil {
		t.Fatalf("close repository: %v", err)
	}
	if err := service.Reload(); err == nil {
		t.Fatal("Reload() on closed repository returned nil")
	}
	if !service.Contains("192.0.2.31") {
		t.Fatal("failed Reload() changed the previous runtime index")
	}
	if err := service.Add(BlacklistIPInput{IP: "192.0.2.32"}); err == nil {
		t.Fatal("Add() on closed repository returned nil")
	}
	if service.Contains("192.0.2.32") {
		t.Fatal("failed Add() published a record")
	}
}

func TestBlacklistServiceReloadKeepsOldIndexAfterMidStreamFailure(t *testing.T) {
	service, repository := newTestBlacklistService(t)
	if err := service.Add(BlacklistIPInput{IP: "192.0.2.30"}); err != nil {
		t.Fatalf("seed service record: %v", err)
	}
	if err := repository.Add(BlacklistIPInput{IP: "192.0.2.31"}); err != nil {
		t.Fatalf("seed second valid record: %v", err)
	}
	future := time.Now().Unix() + 100
	if _, err := repository.db.Exec(`
INSERT INTO blacklist_ip (
    ip, source, reason, enabled, first_seen_at, last_seen_at,
    expire_at, hit_count, created_at, updated_at
) VALUES ('bad-ip', 'test', '', 1, 1, 1, ?, 0, 3, 3)
`, future); err != nil {
		t.Fatalf("insert invalid raw record: %v", err)
	}

	seen := 0
	err := repository.WalkActiveIndex(time.Now().Unix(), func(ip string, _ *int64) error {
		seen++
		if ip == "bad-ip" {
			return errors.New("stop at invalid test row")
		}
		return nil
	})
	if err == nil || seen < 3 {
		t.Fatalf("WalkActiveIndex() error = %v, rows seen = %d; want mid-stream failure after valid rows", err, seen)
	}

	if err := service.Reload(); err == nil {
		t.Fatal("Reload() with an invalid mid-stream row returned nil")
	}
	if !service.Contains("192.0.2.30") {
		t.Fatal("old live index entry was lost after mid-stream Reload() failure")
	}
	if service.Contains("192.0.2.31") {
		t.Fatal("partially loaded entry was published after mid-stream Reload() failure")
	}
}

func TestBlacklistRepositoryImportsLegacyGlobalBlacklistOnce(t *testing.T) {
	repository, dbPath := newTestRepository(t)
	rawIPs := []string{
		"192.0.2.40",
		" 192.0.2.40:443 ",
		"2001:0db8::40",
		"[2001:db8::40]:443",
		"not-an-ip",
	}
	stats, err := repository.ImportLegacyOnce(rawIPs)
	if err != nil {
		t.Fatalf("ImportLegacyOnce() error = %v", err)
	}
	if stats.Total != 5 || stats.Imported != 2 || stats.Duplicates != 2 || stats.Invalid != 1 || stats.SkippedByMarker {
		t.Fatalf("ImportLegacyOnce() stats = %+v, want total=5 imported=2 duplicates=2 invalid=1", stats)
	}
	if len(stats.InvalidSamples) != 1 || stats.InvalidSamples[0] != "not-an-ip" {
		t.Fatalf("invalid samples = %#v, want [not-an-ip]", stats.InvalidSamples)
	}
	count, err := repository.Count()
	if err != nil || count != 2 {
		t.Fatalf("imported count = %d, %v; want 2, nil", count, err)
	}
	if marker, exists, err := repository.GetMeta(legacyImportMarkerKey); err != nil || !exists || marker != "1" {
		t.Fatalf("legacy marker = %q, exists=%t, err=%v; want 1, true, nil", marker, exists, err)
	}

	second, err := repository.ImportLegacyOnce([]string{"192.0.2.41"})
	if err != nil {
		t.Fatalf("second ImportLegacyOnce() error = %v", err)
	}
	if !second.SkippedByMarker {
		t.Fatalf("second import stats = %+v, want skipped by marker", second)
	}
	count, err = repository.Count()
	if err != nil || count != 2 {
		t.Fatalf("count after second import = %d, %v; want 2, nil", count, err)
	}

	if _, err := repository.db.Exec("DELETE FROM blacklist_ip"); err != nil {
		t.Fatalf("delete imported rows: %v", err)
	}
	if err := repository.Close(); err != nil {
		t.Fatalf("close imported repository: %v", err)
	}
	reopened, err := NewBlacklistRepository(dbPath)
	if err != nil {
		t.Fatalf("reopen imported repository: %v", err)
	}
	defer reopened.Close()
	third, err := reopened.ImportLegacyOnce([]string{"192.0.2.42"})
	if err != nil {
		t.Fatalf("third ImportLegacyOnce() error = %v", err)
	}
	if !third.SkippedByMarker {
		t.Fatalf("third import stats = %+v, want skipped by marker", third)
	}
	count, err = reopened.Count()
	if err != nil || count != 0 {
		t.Fatalf("count after marker-protected restart = %d, %v; want 0, nil", count, err)
	}
}

func TestBlacklistRepositoryEmptyLegacyImportWritesMarker(t *testing.T) {
	repository, _ := newTestRepository(t)
	first, err := repository.ImportLegacyOnce(nil)
	if err != nil {
		t.Fatalf("empty ImportLegacyOnce() error = %v", err)
	}
	if first.Imported != 0 || first.Invalid != 0 || first.SkippedByMarker {
		t.Fatalf("empty import stats = %+v, want no rows, no invalid values, and no skip", first)
	}
	if marker, exists, err := repository.GetMeta(legacyImportMarkerKey); err != nil || !exists || marker != "1" {
		t.Fatalf("empty import marker = %q, exists=%t, err=%v; want 1, true, nil", marker, exists, err)
	}

	second, err := repository.ImportLegacyOnce([]string{"192.0.2.100"})
	if err != nil {
		t.Fatalf("second ImportLegacyOnce() error = %v", err)
	}
	if !second.SkippedByMarker {
		t.Fatalf("second empty-import stats = %+v, want skipped by marker", second)
	}
	count, err := repository.Count()
	if err != nil || count != 0 {
		t.Fatalf("count after empty marker import = %d, %v; want 0, nil", count, err)
	}
}

func TestBlacklistRepositoryLegacyImportMarkerFailureRollsBackRows(t *testing.T) {
	repository, _ := newTestRepository(t)
	if _, err := repository.db.Exec(`
CREATE TRIGGER fail_legacy_marker
BEFORE INSERT ON blacklist_meta
WHEN NEW.key = 'legacy_global_blacklist_imported'
BEGIN
    SELECT RAISE(FAIL, 'forced marker failure');
END
`); err != nil {
		t.Fatalf("create marker failure trigger: %v", err)
	}

	if _, err := repository.ImportLegacyOnce([]string{"192.0.2.110", "192.0.2.111"}); err == nil {
		t.Fatal("ImportLegacyOnce() with marker failure returned nil")
	}
	count, err := repository.Count()
	if err != nil || count != 0 {
		t.Fatalf("count after marker failure = %d, %v; want 0, nil", count, err)
	}
	if marker, exists, err := repository.GetMeta(legacyImportMarkerKey); err != nil || exists || marker != "" {
		t.Fatalf("marker after marker failure = %q, exists=%t, err=%v; want empty, false, nil", marker, exists, err)
	}
}

func TestBlacklistRepositoryLegacyImportPreservesExistingMetadata(t *testing.T) {
	repository, _ := newTestRepository(t)
	expireAt := int64(1_800_000_000)
	if err := repository.Add(BlacklistIPInput{
		IP:       "192.0.2.120",
		Source:   "manual",
		Reason:   "keep-me",
		ExpireAt: &expireAt,
	}); err != nil {
		t.Fatalf("seed existing record: %v", err)
	}

	stats, err := repository.ImportLegacyOnce([]string{"192.0.2.120"})
	if err != nil {
		t.Fatalf("ImportLegacyOnce() existing record error = %v", err)
	}
	if stats.Imported != 0 || stats.Duplicates != 1 {
		t.Fatalf("existing record import stats = %+v, want imported=0 duplicates=1", stats)
	}
	got, err := repository.GetByIP("192.0.2.120")
	if err != nil {
		t.Fatalf("read existing record: %v", err)
	}
	if got.Source != "manual" || got.Reason != "keep-me" || got.ExpireAt == nil || *got.ExpireAt != expireAt {
		t.Fatalf("existing metadata changed by import: %+v", got)
	}
}

func TestBlacklistServiceEnableExpiredRecordDoesNotPublish(t *testing.T) {
	service, repository := newTestBlacklistService(t)
	disabled := false
	expired := time.Now().Unix() - 1
	if err := repository.Add(BlacklistIPInput{
		IP:       "198.51.100.90",
		Enabled:  &disabled,
		ExpireAt: &expired,
	}); err != nil {
		t.Fatalf("seed disabled expired record: %v", err)
	}
	if err := service.Reload(); err != nil {
		t.Fatalf("Reload() disabled expired record error = %v", err)
	}
	if err := service.Enable("198.51.100.90"); err != nil {
		t.Fatalf("Enable() expired record error = %v", err)
	}
	got, err := repository.GetByIP("198.51.100.90")
	if err != nil || !got.Enabled {
		t.Fatalf("expired record after Enable() = %+v, err=%v; want enabled in SQLite", got, err)
	}
	if service.Contains("198.51.100.90") {
		t.Fatal("expired record entered runtime index after Enable()")
	}
}

func TestBlacklistServiceCanonicalizesIPv4MappedIPv6(t *testing.T) {
	service, _ := newTestBlacklistService(t)
	if err := service.Add(BlacklistIPInput{IP: "::ffff:192.0.2.10"}); err != nil {
		t.Fatalf("Add() mapped IPv4 error = %v", err)
	}
	for _, rawIP := range []string{"192.0.2.10", "::ffff:192.0.2.10", "192.0.2.10:443"} {
		if !service.Contains(rawIP) {
			t.Errorf("Contains(%q) = false, want true", rawIP)
		}
	}
}

func TestBlacklistServiceConcurrentContainsAndMutations(t *testing.T) {
	service, _ := newTestBlacklistService(t)
	if err := service.Add(BlacklistIPInput{IP: "198.51.100.80"}); err != nil {
		t.Fatalf("seed concurrent service record: %v", err)
	}

	var waitGroup sync.WaitGroup
	for i := 0; i < 4; i++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for j := 0; j < 200; j++ {
				_ = service.Contains("198.51.100.80:443")
				_ = service.Contains("not-an-ip")
			}
		}()
	}
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		for i := 0; i < 50; i++ {
			if err := service.Disable("198.51.100.80"); err != nil {
				t.Errorf("concurrent Disable() error = %v", err)
			}
			if err := service.Enable("198.51.100.80"); err != nil {
				t.Errorf("concurrent Enable() error = %v", err)
			}
		}
	}()
	waitGroup.Wait()
	if !service.Contains("198.51.100.80") {
		t.Fatal("record should be enabled after concurrent mutation test")
	}
}
