package security

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

var (
	benchmarkBoolSink     bool
	benchmarkStringSink   string
	benchmarkIntSink      int
	benchmarkParallelSink uint32
)

func benchmarkBlacklistService(size int) (*BlacklistService, string, string, string, string, string, string) {
	now := time.Now().Unix()
	index := make(map[netip.Addr]int64, size)
	for i := 0; i < size; i++ {
		addr, err := ParseIPAddr(scaleIP(i))
		if err != nil {
			panic(err)
		}
		index[addr] = 0
	}
	hitIPv4 := scaleIP(2)
	hitIPv6 := scaleIP(10)
	expiredIP := scaleIP(1)
	expiredAddr, _ := ParseIPAddr(expiredIP)
	index[expiredAddr] = now - 1
	return &BlacklistService{index: index}, hitIPv4, hitIPv6, expiredIP, "192.0.2.254", "2001:db8:ffff::1", scalePort(hitIPv6)
}

func BenchmarkBlacklistContains(b *testing.B) {
	for _, size := range blacklistScaleSizes {
		size := size
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			service, hitIPv4, hitIPv6, expiredIP, missIPv4, missIPv6, hitIPv6Port := benchmarkBlacklistService(size)
			cases := []struct {
				name  string
				input string
			}{
				{name: "IPv4Hit", input: hitIPv4},
				{name: "IPv4Miss", input: missIPv4},
				{name: "IPv4PortHit", input: hitIPv4 + ":443"},
				{name: "IPv6Hit", input: hitIPv6},
				{name: "IPv6Miss", input: missIPv6},
				{name: "IPv6PortHit", input: hitIPv6Port},
				{name: "Expired", input: expiredIP},
			}
			for _, benchmarkCase := range cases {
				benchmarkCase := benchmarkCase
				b.Run(benchmarkCase.name, func(b *testing.B) {
					for i := 0; i < b.N; i++ {
						benchmarkBoolSink = service.Contains(benchmarkCase.input)
					}
					runtime.KeepAlive(service)
				})
				b.Run(benchmarkCase.name+"/RunParallel", func(b *testing.B) {
					b.RunParallel(func(pb *testing.PB) {
						var result bool
						for pb.Next() {
							result = service.Contains(benchmarkCase.input)
						}
						if result {
							atomic.StoreUint32(&benchmarkParallelSink, 1)
						} else {
							atomic.StoreUint32(&benchmarkParallelSink, 0)
						}
					})
					runtime.KeepAlive(service)
				})
			}
		})
	}
}

func benchmarkRepository(b *testing.B, size int) *Repository {
	b.Helper()
	entries, _ := buildScaleEntries(size, time.Now().Unix())
	repository, err := NewBlacklistRepository(filepath.Join(b.TempDir(), "blacklist.db"))
	if err != nil {
		b.Fatalf("NewBlacklistRepository() error = %v", err)
	}
	if err := repository.BulkInsert(entries); err != nil {
		_ = repository.Close()
		b.Fatalf("BulkInsert(%d) error = %v", size, err)
	}
	entries = nil
	runtime.GC()
	return repository
}

func BenchmarkBlacklistBulkInsertScale(b *testing.B) {
	for _, size := range blacklistScaleSizes {
		size := size
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			entries, _ := buildScaleEntries(size, time.Now().Unix())
			b.SetBytes(int64(size))
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				b.StopTimer()
				dbPath := filepath.Join(b.TempDir(), fmt.Sprintf("bulk-%d.db", iteration))
				repository, err := NewBlacklistRepository(dbPath)
				if err != nil {
					b.Fatalf("NewBlacklistRepository() error = %v", err)
				}
				b.StartTimer()
				err = repository.BulkInsert(entries)
				b.StopTimer()
				closeErr := repository.Close()
				if err != nil {
					b.Fatalf("BulkInsert(%d) error = %v", size, err)
				}
				if closeErr != nil {
					b.Fatalf("close benchmark repository: %v", closeErr)
				}
				b.StartTimer()
			}
		})
	}
}

func BenchmarkBlacklistRepositoryScale(b *testing.B) {
	for _, size := range blacklistScaleSizes {
		size := size
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			b.StopTimer()
			repository := benchmarkRepository(b, size)
			b.Cleanup(func() { _ = repository.Close() })
			b.StartTimer()

			b.Run("GetByIP/First", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					entry, err := repository.GetByIP(scaleIP(0))
					if err != nil {
						b.Fatal(err)
					}
					benchmarkStringSink = entry.IP
				}
			})
			b.Run("GetByIP/Middle", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					entry, err := repository.GetByIP(scaleIP(size / 2))
					if err != nil {
						b.Fatal(err)
					}
					benchmarkStringSink = entry.IP
				}
			})
			b.Run("GetByIP/Tail", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					entry, err := repository.GetByIP(scaleIP(size - 1))
					if err != nil {
						b.Fatal(err)
					}
					benchmarkStringSink = entry.IP
				}
			})
			b.Run("GetByIP/Miss", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					entry, err := repository.GetByIP("192.0.2.254")
					if entry != nil || !errors.Is(err, ErrNotFound) {
						b.Fatalf("entry=%+v err=%v", entry, err)
					}
					benchmarkBoolSink = true
				}
			})
			b.Run("List/FirstPage", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					items, err := repository.ListWithOptions(ListOptions{Offset: 0, Limit: 50})
					if err != nil {
						b.Fatal(err)
					}
					benchmarkIntSink = len(items)
				}
			})
			b.Run("List/MiddlePage", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					items, err := repository.ListWithOptions(ListOptions{Offset: size / 2, Limit: 50})
					if err != nil {
						b.Fatal(err)
					}
					benchmarkIntSink = len(items)
				}
			})
			b.Run("List/TailPage", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					items, err := repository.ListWithOptions(ListOptions{Offset: size - 50, Limit: 50})
					if err != nil {
						b.Fatal(err)
					}
					benchmarkIntSink = len(items)
				}
			})
			b.Run("Stats", func(b *testing.B) {
				now := time.Now().Unix()
				for i := 0; i < b.N; i++ {
					stats, err := repository.Stats(now)
					if err != nil {
						b.Fatal(err)
					}
					benchmarkIntSink = int(stats.Total)
				}
			})
		})
	}
}
