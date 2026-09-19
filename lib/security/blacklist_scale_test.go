package security

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const blacklistScaleEnv = "NPS_BLACKLIST_SCALE"

var blacklistScaleSizes = []int{100_000, 500_000, 1_000_000}

type blacklistScaleExpected struct {
	stats         BlacklistStats
	activeRows    int64
	manualEnabled int64
}

type blacklistDBSizes struct {
	main  int64
	wal   int64
	shm   int64
	total int64
}

func requireBlacklistScale(t *testing.T) {
	t.Helper()
	if os.Getenv(blacklistScaleEnv) != "1" {
		t.Skipf("set %s=1 to run the explicit large-scale blacklist test", blacklistScaleEnv)
	}
}

func scaleIP(index int) string {
	if index%10 == 0 {
		var raw [16]byte
		raw[0] = 0x20
		raw[1] = 0x01
		raw[2] = 0x0d
		raw[3] = 0xb8
		binary.BigEndian.PutUint64(raw[8:], uint64(index))
		return netip.AddrFrom16(raw).String()
	}
	return netip.AddrFrom4([4]byte{
		10,
		byte(index >> 16),
		byte(index >> 8),
		byte(index),
	}).String()
}

func scalePort(raw string) string {
	if strings.Contains(raw, ":") {
		return "[" + raw + "]:443"
	}
	return raw + ":443"
}

func buildScaleEntries(count int, now int64) ([]BlacklistIP, blacklistScaleExpected) {
	entries := make([]BlacklistIP, count)
	expected := blacklistScaleExpected{}
	sources := [...]string{"manual", "import", "auto"}
	for index := 0; index < count; index++ {
		enabled := index%7 != 0
		source := sources[index%len(sources)]
		var expireAt *int64
		switch index % 13 {
		case 0:
			expired := now - 3600
			expireAt = &expired
		case 1:
			future := now + 86400
			expireAt = &future
		}
		createdAt := now - int64(count-index)
		entries[index] = BlacklistIP{
			IP:          scaleIP(index),
			Source:      source,
			Enabled:     enabled,
			FirstSeenAt: now - 100,
			LastSeenAt:  now - 10,
			ExpireAt:    expireAt,
			CreatedAt:   createdAt,
			UpdatedAt:   createdAt,
		}

		expected.stats.Total++
		if enabled {
			expected.stats.Enabled++
		} else {
			expected.stats.Disabled++
		}
		switch source {
		case "manual":
			expected.stats.Manual++
			if enabled {
				expected.manualEnabled++
			}
		case "import":
			expected.stats.Import++
		case "auto":
			expected.stats.Auto++
		}
		if expireAt != nil && *expireAt <= now {
			expected.stats.Expired++
		}
		if enabled && (expireAt == nil || *expireAt > now) {
			expected.stats.Active++
			expected.activeRows++
		}
	}
	return entries, expected
}

func dbFileSizes(path string) blacklistDBSizes {
	var sizes blacklistDBSizes
	for _, file := range []struct {
		suffix string
		dest   *int64
	}{
		{suffix: "", dest: &sizes.main},
		{suffix: "-wal", dest: &sizes.wal},
		{suffix: "-shm", dest: &sizes.shm},
	} {
		info, err := os.Stat(path + file.suffix)
		if err == nil {
			*file.dest = info.Size()
		}
	}
	sizes.total = sizes.main + sizes.wal + sizes.shm
	return sizes
}

func indexSize(service *BlacklistService) int64 {
	service.mapMu.RLock()
	defer service.mapMu.RUnlock()
	return int64(len(service.index))
}

func measureDuration(iterations int, fn func()) time.Duration {
	start := time.Now()
	for i := 0; i < iterations; i++ {
		fn()
	}
	return time.Since(start)
}

func explainQueryPlan(t *testing.T, repository *Repository, query string, args ...any) string {
	t.Helper()
	rows, err := repository.db.Query("EXPLAIN QUERY PLAN "+query, args...)
	if err != nil {
		t.Fatalf("EXPLAIN QUERY PLAN error: %v", err)
	}
	defer rows.Close()
	var details []string
	for rows.Next() {
		var id, parent, notUsed int
		var detail string
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			t.Fatalf("scan query plan: %v", err)
		}
		details = append(details, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate query plan: %v", err)
	}
	return strings.Join(details, " | ")
}

func TestBlacklistExactIPQueryPlanUsesUniqueIndex(t *testing.T) {
	repository, _ := newTestRepository(t)
	if err := repository.Add(BlacklistIPInput{IP: "192.0.2.200"}); err != nil {
		t.Fatalf("seed exact IP: %v", err)
	}
	plan := explainQueryPlan(t, repository,
		"SELECT "+selectColumns+" FROM blacklist_ip WHERE ip = ?", "192.0.2.200")
	if !strings.Contains(plan, "uk_blacklist_ip") {
		t.Fatalf("exact IP query plan = %q, want uk_blacklist_ip", plan)
	}
}

func TestBlacklistServiceContainsWorksAfterRepositoryClose(t *testing.T) {
	repository, _ := newTestRepository(t)
	service, _, err := NewBlacklistService(repository, nil)
	if err != nil {
		t.Fatalf("NewBlacklistService() error = %v", err)
	}
	if err := service.Add(BlacklistIPInput{IP: "198.51.100.200"}); err != nil {
		t.Fatalf("add active IP: %v", err)
	}
	expired := time.Now().Unix() - 1
	if err := service.Add(BlacklistIPInput{IP: "198.51.100.201", ExpireAt: &expired}); err != nil {
		t.Fatalf("add expired IP: %v", err)
	}
	if err := repository.Close(); err != nil {
		t.Fatalf("close repository: %v", err)
	}
	if !service.Contains("198.51.100.200:443") {
		t.Fatal("active IP is not contained after repository close")
	}
	if service.Contains("198.51.100.201") {
		t.Fatal("expired IP is contained after repository close")
	}
	if service.Contains("198.51.100.202") {
		t.Fatal("unknown IP is contained after repository close")
	}
	if err := service.Close(); err != nil {
		t.Fatalf("close service: %v", err)
	}
}

func TestBlacklistServiceDatabaseMapConsistency(t *testing.T) {
	service, repository := newTestBlacklistService(t)
	if err := service.Add(BlacklistIPInput{IP: "198.51.100.210"}); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	if entry, err := repository.GetByIP("198.51.100.210"); err != nil || !entry.Enabled || !service.Contains("198.51.100.210") {
		t.Fatalf("after Add(): entry=%+v err=%v contains=%t", entry, err, service.Contains("198.51.100.210"))
	}

	if err := service.Disable("198.51.100.210"); err != nil {
		t.Fatalf("Disable() error = %v", err)
	}
	entry, err := repository.GetByIP("198.51.100.210")
	if err != nil || entry.Enabled || service.Contains("198.51.100.210") {
		t.Fatalf("after Disable(): entry=%+v err=%v contains=%t", entry, err, service.Contains("198.51.100.210"))
	}

	if err := service.Enable("198.51.100.210"); err != nil {
		t.Fatalf("Enable() error = %v", err)
	}
	entry, err = repository.GetByIP("198.51.100.210")
	if err != nil || !entry.Enabled || !service.Contains("198.51.100.210") {
		t.Fatalf("after Enable(): entry=%+v err=%v contains=%t", entry, err, service.Contains("198.51.100.210"))
	}

	if err := service.Delete("198.51.100.210"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := repository.GetByIP("198.51.100.210"); !errors.Is(err, ErrNotFound) || service.Contains("198.51.100.210") {
		t.Fatalf("after Delete(): err=%v contains=%t", err, service.Contains("198.51.100.210"))
	}

	expired := time.Now().Unix() - 1
	if err := service.Add(BlacklistIPInput{IP: "198.51.100.211", ExpireAt: &expired}); err != nil {
		t.Fatalf("Add(expired) error = %v", err)
	}
	if entry, err := repository.GetByIP("198.51.100.211"); err != nil || !entry.Enabled || service.Contains("198.51.100.211") {
		t.Fatalf("after Add(expired): entry=%+v err=%v contains=%t", entry, err, service.Contains("198.51.100.211"))
	}

	if err := repository.Close(); err != nil {
		t.Fatalf("close repository for failure test: %v", err)
	}
	if err := service.Disable("198.51.100.211"); err == nil {
		t.Fatal("Disable() on closed repository returned nil")
	}
	if service.Contains("198.51.100.211") {
		t.Fatal("failed DB mutation changed runtime index")
	}
}

func TestBlacklistServiceConcurrentContainsAndMutationsHighIntensity(t *testing.T) {
	service, _ := newTestBlacklistService(t)
	if err := service.Add(BlacklistIPInput{IP: "198.51.100.220"}); err != nil {
		t.Fatalf("seed concurrent service record: %v", err)
	}

	const readers = 12
	const containsPerReader = 2000
	var waitGroup sync.WaitGroup
	for reader := 0; reader < readers; reader++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for i := 0; i < containsPerReader; i++ {
				_ = service.Contains("198.51.100.220:443")
				_ = service.Contains("2001:db8::220")
				_ = service.Contains("not-an-ip")
			}
		}()
	}
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		for i := 0; i < 100; i++ {
			if err := service.Disable("198.51.100.220"); err != nil {
				t.Errorf("concurrent Disable() error = %v", err)
			}
			if err := service.Enable("198.51.100.220"); err != nil {
				t.Errorf("concurrent Enable() error = %v", err)
			}
		}
	}()
	waitGroup.Wait()

	if err := service.Enable("198.51.100.220"); err != nil {
		t.Fatalf("final Enable() error = %v", err)
	}
	if !service.Contains("198.51.100.220") {
		t.Fatal("record should be enabled after high-intensity concurrent test")
	}
}

func scaleBoolPointer(value bool) *bool {
	return &value
}

func TestBlacklistScaleReport(t *testing.T) {
	requireBlacklistScale(t)
	for _, scale := range blacklistScaleSizes {
		scale := scale
		t.Run(strconv.Itoa(scale), func(t *testing.T) {
			runBlacklistScaleReport(t, scale)
		})
	}
}

func runBlacklistScaleReport(t *testing.T, scale int) {
	t.Helper()
	now := time.Now().Unix()
	entries, expected := buildScaleEntries(scale, now)
	dbPath := filepath.Join(t.TempDir(), "blacklist.db")
	repository, err := NewBlacklistRepository(dbPath)
	if err != nil {
		t.Fatalf("NewBlacklistRepository() error = %v", err)
	}

	started := time.Now()
	if err := repository.BulkInsert(entries); err != nil {
		_ = repository.Close()
		t.Fatalf("BulkInsert(%d) error = %v", scale, err)
	}
	insertDuration := time.Since(started)
	rows, err := repository.Count()
	if err != nil {
		_ = repository.Close()
		t.Fatalf("Count() after BulkInsert(%d): %v", scale, err)
	}
	if rows != int64(scale) {
		_ = repository.Close()
		t.Fatalf("BulkInsert(%d) rows = %d, want %d", scale, rows, scale)
	}
	openSizes := dbFileSizes(dbPath)
	if err := repository.Close(); err != nil {
		t.Fatalf("close seed repository: %v", err)
	}
	closedSizes := dbFileSizes(dbPath)

	// The generated []BlacklistIP is test input, not repository-owned memory.
	// Release it before measuring the real startup path.
	entries = nil
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	loadStarted := time.Now()
	loadedRepository, err := NewBlacklistRepository(dbPath)
	if err != nil {
		t.Fatalf("reopen scale repository: %v", err)
	}
	service, _, err := NewBlacklistService(loadedRepository, nil)
	if err != nil {
		_ = loadedRepository.Close()
		t.Fatalf("NewBlacklistService(%d) error = %v", scale, err)
	}
	loadDuration := time.Since(loadStarted)
	runtime.ReadMemStats(&after)
	loadedIndexSize := indexSize(service)
	if loadedIndexSize != expected.activeRows {
		_ = service.Close()
		t.Fatalf("startup index size = %d, want %d active rows", loadedIndexSize, expected.activeRows)
	}
	runtime.KeepAlive(service)

	statsStarted := time.Now()
	stats, err := service.Stats(now)
	statsDuration := time.Since(statsStarted)
	if err != nil {
		_ = service.Close()
		t.Fatalf("Stats(%d) error = %v", scale, err)
	}
	if stats != expected.stats {
		_ = service.Close()
		t.Fatalf("Stats(%d) = %+v, want %+v", scale, stats, expected.stats)
	}

	firstIP := scaleIP(0)
	middleIP := scaleIP(scale / 2)
	tailIP := scaleIP(scale - 1)
	missingIP := "192.0.2.254"
	getIterations := 3
	getFirst := measureDuration(getIterations, func() {
		entry, getErr := service.GetByIP(firstIP)
		if getErr != nil || entry == nil {
			t.Fatalf("GetByIP(first=%q): entry=%+v err=%v", firstIP, entry, getErr)
		}
	})
	getMiddle := measureDuration(getIterations, func() {
		entry, getErr := service.GetByIP(middleIP)
		if getErr != nil || entry == nil {
			t.Fatalf("GetByIP(middle=%q): entry=%+v err=%v", middleIP, entry, getErr)
		}
	})
	getTail := measureDuration(getIterations, func() {
		entry, getErr := service.GetByIP(tailIP)
		if getErr != nil || entry == nil {
			t.Fatalf("GetByIP(tail=%q): entry=%+v err=%v", tailIP, entry, getErr)
		}
	})
	getMiss := measureDuration(getIterations, func() {
		entry, getErr := service.GetByIP(missingIP)
		if entry != nil || !errors.Is(getErr, ErrNotFound) {
			t.Fatalf("GetByIP(miss=%q): entry=%+v err=%v", missingIP, entry, getErr)
		}
	})

	listIterations := 3
	firstPage := measureDuration(listIterations, func() {
		items, listErr := service.ListPage(ListOptions{Offset: 0, Limit: 50})
		if listErr != nil || len(items.Items) != 50 {
			t.Fatalf("ListPage(first): items=%d err=%v", len(items.Items), listErr)
		}
	})
	middlePage := measureDuration(listIterations, func() {
		items, listErr := service.ListPage(ListOptions{Offset: scale / 2, Limit: 50})
		if listErr != nil || len(items.Items) != 50 {
			t.Fatalf("ListPage(middle): items=%d err=%v", len(items.Items), listErr)
		}
	})
	tailOffset := scale - 50
	tailPage := measureDuration(listIterations, func() {
		items, listErr := service.ListPage(ListOptions{Offset: tailOffset, Limit: 50})
		if listErr != nil || len(items.Items) != 50 {
			t.Fatalf("ListPage(tail): items=%d err=%v", len(items.Items), listErr)
		}
	})

	filterCases := []struct {
		name      string
		options   ListOptions
		wantTotal int64
	}{
		{name: "manual", options: ListOptions{Source: "manual"}, wantTotal: expected.stats.Manual},
		{name: "enabled", options: ListOptions{Enabled: scaleBoolPointer(true)}, wantTotal: expected.stats.Enabled},
		{name: "manual_enabled", options: ListOptions{Source: "manual", Enabled: scaleBoolPointer(true)}, wantTotal: expected.manualEnabled},
	}
	for _, filter := range filterCases {
		filter := filter
		items, listErr := service.ListPage(ListOptions{Limit: 50, Source: filter.options.Source, Enabled: filter.options.Enabled})
		if listErr != nil || int64(len(items.Items)) == 0 || items.Total != filter.wantTotal {
			t.Fatalf("filtered ListPage(%s): items=%d total=%d err=%v want total=%d", filter.name, len(items.Items), items.Total, listErr, filter.wantTotal)
		}
		countStarted := time.Now()
		count, countErr := loadedRepository.CountWithOptions(filter.options)
		countDuration := time.Since(countStarted)
		if countErr != nil || count != filter.wantTotal {
			t.Fatalf("CountWithOptions(%s): count=%d err=%v want=%d", filter.name, count, countErr, filter.wantTotal)
		}
		listStarted := time.Now()
		_, listErr = loadedRepository.ListWithOptions(ListOptions{Limit: 50, Source: filter.options.Source, Enabled: filter.options.Enabled})
		listDuration := time.Since(listStarted)
		if listErr != nil {
			t.Fatalf("ListWithOptions(%s): %v", filter.name, listErr)
		}
		t.Logf("BLACKLIST_FILTER scale=%d filter=%s rows=%d list_page_ms=%.3f count_ms=%.3f plan=%s", scale, filter.name, count, float64(listDuration)/float64(time.Millisecond), float64(countDuration)/float64(time.Millisecond), explainQueryPlan(t, loadedRepository, filteredPlanQuery(filter.options), filteredPlanArgs(filter.options)...))
	}

	exactPlan := explainQueryPlan(t, loadedRepository,
		"SELECT "+selectColumns+" FROM blacklist_ip WHERE ip = ?", firstIP)
	sourcePlan := explainQueryPlan(t, loadedRepository,
		"SELECT id FROM blacklist_ip WHERE source = ?", "manual")
	enabledPlan := explainQueryPlan(t, loadedRepository,
		"SELECT id FROM blacklist_ip WHERE enabled = ?", 1)
	combinedPlan := explainQueryPlan(t, loadedRepository,
		"SELECT id FROM blacklist_ip WHERE source = ? AND enabled = ?", "manual", 1)

	if err := service.Close(); err != nil {
		t.Fatalf("close loaded service: %v", err)
	}

	restartRepository, err := NewBlacklistRepository(dbPath)
	if err != nil {
		t.Fatalf("reopen scale repository for restart check: %v", err)
	}
	restartService, restartStats, err := NewBlacklistService(restartRepository, nil)
	if err != nil {
		_ = restartRepository.Close()
		t.Fatalf("restart NewBlacklistService(%d): %v", scale, err)
	}
	restartActiveRows, err := restartRepository.CountActive(now)
	if err != nil {
		_ = restartService.Close()
		t.Fatalf("CountActive after restart: %v", err)
	}
	if restartActiveRows != indexSize(restartService) {
		_ = restartService.Close()
		t.Fatalf("restart active rows=%d, runtime index=%d", restartActiveRows, indexSize(restartService))
	}
	marker, markerExists, err := restartRepository.GetMeta(legacyImportMarkerKey)
	if err != nil || !markerExists || marker != "1" || !restartStats.SkippedByMarker {
		_ = restartService.Close()
		t.Fatalf("restart marker=%q exists=%t stats=%+v err=%v", marker, markerExists, restartStats, err)
	}
	var journalMode string
	if err := restartRepository.db.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil {
		_ = restartService.Close()
		t.Fatalf("read restart journal mode: %v", err)
	}
	if journalMode != "wal" {
		_ = restartService.Close()
		t.Fatalf("restart journal_mode=%q, want wal", journalMode)
	}
	if err := restartService.Close(); err != nil {
		t.Fatalf("close restart service: %v", err)
	}

	heapDelta := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	totalAllocDelta := int64(after.TotalAlloc) - int64(before.TotalAlloc)
	t.Logf("BLACKLIST_SCALE scale=%d seed=deterministic-ipv4-ipv6 input_rows=%d rows=%d bulk_ms=%.3f rows_per_sec=%.2f db_main_bytes=%d db_wal_bytes=%d db_shm_bytes=%d db_total_bytes=%d db_after_close_main_bytes=%d db_after_close_wal_bytes=%d db_after_close_shm_bytes=%d db_after_close_total_bytes=%d startup_ms=%.3f runtime_index=%d heap_delta=%d total_alloc_delta=%d num_gc_delta=%d stats_ms=%.3f get_first_ms=%.3f get_middle_ms=%.3f get_tail_ms=%.3f get_miss_ms=%.3f list_first_ms=%.3f list_middle_ms=%.3f list_tail_ms=%.3f query_plan_exact=%q query_plan_source=%q query_plan_enabled=%q query_plan_source_enabled=%q journal_mode=%s marker=1 heap_note=go_heap_approximate", scale, scale, rows, float64(insertDuration)/float64(time.Millisecond), float64(scale)/insertDuration.Seconds(), openSizes.main, openSizes.wal, openSizes.shm, openSizes.total, closedSizes.main, closedSizes.wal, closedSizes.shm, closedSizes.total, float64(loadDuration)/float64(time.Millisecond), loadedIndexSize, heapDelta, totalAllocDelta, after.NumGC-before.NumGC, float64(statsDuration)/float64(time.Millisecond), float64(getFirst)/float64(time.Millisecond), float64(getMiddle)/float64(time.Millisecond), float64(getTail)/float64(time.Millisecond), float64(getMiss)/float64(time.Millisecond), float64(firstPage)/float64(time.Millisecond), float64(middlePage)/float64(time.Millisecond), float64(tailPage)/float64(time.Millisecond), exactPlan, sourcePlan, enabledPlan, combinedPlan, journalMode)
}

func filteredPlanQuery(options ListOptions) string {
	switch {
	case options.Source != "" && options.Enabled != nil:
		return "SELECT id FROM blacklist_ip WHERE source = ? AND enabled = ?"
	case options.Source != "":
		return "SELECT id FROM blacklist_ip WHERE source = ?"
	default:
		return "SELECT id FROM blacklist_ip WHERE enabled = ?"
	}
}

func filteredPlanArgs(options ListOptions) []any {
	if options.Source != "" && options.Enabled != nil {
		return []any{options.Source, boolValue(*options.Enabled)}
	}
	if options.Source != "" {
		return []any{options.Source}
	}
	return []any{boolValue(*options.Enabled)}
}

func buildLegacyScaleInput(count int) []string {
	rawIPs := make([]string, 0, count)
	for index := 0; index < count; index++ {
		rawIP := scaleIP(index)
		if index > 0 && index%997 == 0 {
			// Use the preceding canonical IP so this is an actual duplicate,
			// not merely a new row written with a port suffix.
			rawIP = scalePort(scaleIP(index - 1))
		}
		if index%1999 == 0 {
			rawIP = fmt.Sprintf("not-an-ip-%d", index)
		}
		rawIPs = append(rawIPs, rawIP)
	}
	return rawIPs
}

func TestBlacklistLegacyScale(t *testing.T) {
	requireBlacklistScale(t)
	for _, scale := range []int{100_000, 500_000} {
		scale := scale
		t.Run(strconv.Itoa(scale), func(t *testing.T) {
			rawIPs := buildLegacyScaleInput(scale)
			dbPath := filepath.Join(t.TempDir(), "blacklist.db")
			repository, err := NewBlacklistRepository(dbPath)
			if err != nil {
				t.Fatalf("NewBlacklistRepository() error = %v", err)
			}
			started := time.Now()
			stats, err := repository.ImportLegacyOnce(rawIPs)
			firstDuration := time.Since(started)
			if err != nil {
				_ = repository.Close()
				t.Fatalf("ImportLegacyOnce(%d) error = %v", scale, err)
			}
			if stats.Total != len(rawIPs) || stats.Imported+stats.Duplicates+stats.Invalid != stats.Total {
				_ = repository.Close()
				t.Fatalf("legacy stats=%+v, total input=%d", stats, len(rawIPs))
			}
			count, err := repository.Count()
			if err != nil || count != int64(stats.Imported) {
				_ = repository.Close()
				t.Fatalf("legacy rows=%d imported=%d err=%v", count, stats.Imported, err)
			}
			if err := repository.Close(); err != nil {
				t.Fatalf("close legacy repository: %v", err)
			}
			sizes := dbFileSizes(dbPath)

			reopened, err := NewBlacklistRepository(dbPath)
			if err != nil {
				t.Fatalf("reopen legacy repository: %v", err)
			}
			started = time.Now()
			second, err := reopened.ImportLegacyOnce([]string{scaleIP(scale + 1)})
			secondDuration := time.Since(started)
			if err != nil {
				_ = reopened.Close()
				t.Fatalf("second ImportLegacyOnce(%d) error = %v", scale, err)
			}
			if !second.SkippedByMarker {
				_ = reopened.Close()
				t.Fatalf("second legacy import stats=%+v, want marker skip", second)
			}
			secondCount, err := reopened.Count()
			if err != nil || secondCount != count {
				_ = reopened.Close()
				t.Fatalf("rows after marker restart=%d before=%d err=%v", secondCount, count, err)
			}
			marker, exists, err := reopened.GetMeta(legacyImportMarkerKey)
			if err != nil || !exists || marker != "1" {
				_ = reopened.Close()
				t.Fatalf("legacy marker=%q exists=%t err=%v", marker, exists, err)
			}
			if err := reopened.Close(); err != nil {
				t.Fatalf("close reopened legacy repository: %v", err)
			}
			t.Logf("BLACKLIST_LEGACY_SCALE scale=%d input_rows=%d imported=%d duplicates=%d invalid=%d first_ms=%.3f second_marker_ms=%.3f db_main_bytes=%d db_wal_bytes=%d db_shm_bytes=%d db_total_bytes=%d marker=1", scale, stats.Total, stats.Imported, stats.Duplicates, stats.Invalid, float64(firstDuration)/float64(time.Millisecond), float64(secondDuration)/float64(time.Millisecond), sizes.main, sizes.wal, sizes.shm, sizes.total)
		})
	}
}
