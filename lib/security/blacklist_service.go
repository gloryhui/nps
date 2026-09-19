package security

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// BlacklistService is the single runtime owner of the global blacklist
// index. SQLite remains authoritative for persistence; index is authoritative
// only for the proxy request hot path.
type BlacklistService struct {
	writeMu sync.Mutex
	mapMu   sync.RWMutex

	repo  *Repository
	index map[netip.Addr]int64

	closeOnce sync.Once
	closeErr  error
}

// BlacklistListResult contains one SQLite-paginated management result.
type BlacklistListResult struct {
	Items  []BlacklistIP
	Total  int64
	Offset int
	Limit  int
}

// BlacklistStats contains aggregate management counters.
type BlacklistStats struct {
	Total    int64
	Enabled  int64
	Disabled int64
	Manual   int64
	Import   int64
	Auto     int64
	Expired  int64
	Active   int64
}

// NewBlacklistService imports legacy records once, then publishes a complete
// active index. A load failure leaves no partially initialized service.
func NewBlacklistService(repo *Repository, legacyIPs []string) (*BlacklistService, LegacyImportStats, error) {
	if repo == nil {
		return nil, LegacyImportStats{}, errors.New("blacklist repository is nil")
	}
	stats, err := repo.ImportLegacyOnce(legacyIPs)
	if err != nil {
		return nil, stats, fmt.Errorf("legacy blacklist migration: %w", err)
	}

	service := &BlacklistService{
		repo:  repo,
		index: make(map[netip.Addr]int64),
	}
	if err := service.Reload(); err != nil {
		return nil, stats, fmt.Errorf("load runtime blacklist index: %w", err)
	}
	return service, stats, nil
}

// Reload streams active records into a new index and publishes it only after
// the complete database read succeeds. A failed reload leaves the old index
// untouched.
func (s *BlacklistService) Reload() error {
	if s == nil || s.repo == nil {
		return errors.New("blacklist service is not initialized")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	now := time.Now().Unix()
	count, err := s.repo.CountActive(now)
	if err != nil {
		return err
	}
	if count < 0 {
		return errors.New("blacklist active row count is negative")
	}
	maxInt := int64(^uint(0) >> 1)
	if count > maxInt {
		return fmt.Errorf("blacklist active row count %d exceeds map capacity", count)
	}

	newIndex := make(map[netip.Addr]int64, int(count))
	if err := s.repo.WalkActiveIndex(now, func(ip string, expireAt *int64) error {
		addr, err := ParseIPAddr(ip)
		if err != nil {
			return err
		}
		newIndex[addr] = expireValue(expireAt)
		return nil
	}); err != nil {
		return err
	}

	s.mapMu.Lock()
	s.index = newIndex
	s.mapMu.Unlock()
	return nil
}

// Contains checks only the in-memory index. It never accesses SQLite,
// updates hit counters, or writes logs.
func (s *BlacklistService) Contains(rawAddr string) bool {
	if s == nil {
		return false
	}
	addr, err := ParseIPAddr(rawAddr)
	if err != nil {
		return false
	}

	s.mapMu.RLock()
	expireAt, ok := s.index[addr]
	s.mapMu.RUnlock()
	if !ok {
		return false
	}
	return expireAt == 0 || expireAt > time.Now().Unix()
}

// GetByIP reads one management record while coordinating with Close and
// mutations. It never changes the runtime index.
func (s *BlacklistService) GetByIP(rawIP string) (*BlacklistIP, error) {
	if s == nil || s.repo == nil {
		return nil, errors.New("blacklist service is not initialized")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.repo.GetByIP(rawIP)
}

// ListPage performs the row query and filtered count under one management
// read lock so both results come from one serialized repository operation.
func (s *BlacklistService) ListPage(options ListOptions) (BlacklistListResult, error) {
	if s == nil || s.repo == nil {
		return BlacklistListResult{}, errors.New("blacklist service is not initialized")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	items, err := s.repo.ListWithOptions(options)
	if err != nil {
		return BlacklistListResult{}, err
	}
	total, err := s.repo.CountWithOptions(options)
	if err != nil {
		return BlacklistListResult{}, err
	}
	return BlacklistListResult{Items: items, Total: total, Offset: options.Offset, Limit: options.Limit}, nil
}

// Stats returns SQLite aggregate counters using the supplied request time for
// both expired and active calculations. It never changes the runtime index.
func (s *BlacklistService) Stats(now int64) (BlacklistStats, error) {
	if s == nil || s.repo == nil {
		return BlacklistStats{}, errors.New("blacklist service is not initialized")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.repo.Stats(now)
}

// Add persists a record before publishing its eligible state to the runtime
// index. A disabled or already-expired record remains in SQLite but is not
// published.
func (s *BlacklistService) Add(input BlacklistIPInput) error {
	if s == nil || s.repo == nil {
		return errors.New("blacklist service is not initialized")
	}
	addr, err := ParseIPAddr(input.IP)
	if err != nil {
		return err
	}
	input.IP = addr.String()
	entry, err := prepareEntry(inputToEntry(input))
	if err != nil {
		return err
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.repo.Add(input); err != nil {
		return err
	}
	s.publishEntry(entry, time.Now().Unix())
	return nil
}

// Delete removes the persistent record before removing it from the runtime
// index. A failed database operation cannot dirty the index.
func (s *BlacklistService) Delete(rawIP string) error {
	return s.mutateIP(rawIP, func(addr netip.Addr) error {
		if err := s.repo.Delete(addr.String()); err != nil {
			return err
		}
		s.mapMu.Lock()
		delete(s.index, addr)
		s.mapMu.Unlock()
		return nil
	})
}

// Disable disables the persistent record before removing it from the runtime
// index.
func (s *BlacklistService) Disable(rawIP string) error {
	return s.mutateIP(rawIP, func(addr netip.Addr) error {
		if err := s.repo.Disable(addr.String()); err != nil {
			return err
		}
		s.mapMu.Lock()
		delete(s.index, addr)
		s.mapMu.Unlock()
		return nil
	})
}

// Enable reads the record before the mutation, persists the enabled state,
// then publishes it only when it is still within its expiry window.
func (s *BlacklistService) Enable(rawIP string) error {
	if s == nil || s.repo == nil {
		return errors.New("blacklist service is not initialized")
	}
	addr, err := ParseIPAddr(rawIP)
	if err != nil {
		return err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	entry, err := s.repo.GetByIP(addr.String())
	if err != nil {
		return err
	}
	if err := s.repo.Enable(addr.String()); err != nil {
		return err
	}
	entry.Enabled = true
	s.publishEntry(*entry, time.Now().Unix())
	return nil
}

func (s *BlacklistService) mutateIP(rawIP string, mutation func(netip.Addr) error) error {
	if s == nil || s.repo == nil {
		return errors.New("blacklist service is not initialized")
	}
	addr, err := ParseIPAddr(rawIP)
	if err != nil {
		return err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return mutation(addr)
}

func (s *BlacklistService) publishEntry(entry BlacklistIP, now int64) {
	addr, err := ParseIPAddr(entry.IP)
	if err != nil || !entry.Enabled || !isActive(entry.ExpireAt, now) {
		if err == nil {
			s.mapMu.Lock()
			delete(s.index, addr)
			s.mapMu.Unlock()
		}
		return
	}
	s.mapMu.Lock()
	s.index[addr] = expireValue(entry.ExpireAt)
	s.mapMu.Unlock()
}

func isActive(expireAt *int64, now int64) bool {
	return expireAt == nil || *expireAt > now
}

func expireValue(expireAt *int64) int64 {
	if expireAt == nil {
		return 0
	}
	return *expireAt
}

// Close is idempotent and closes the repository without holding the map
// lock. Mutations already in progress complete before the close begins.
func (s *BlacklistService) Close() error {
	if s == nil {
		return nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.closeOnce.Do(func() {
		if s.repo != nil {
			s.closeErr = s.repo.Close()
		}
	})
	return s.closeErr
}

var defaultService struct {
	sync.RWMutex
	service *BlacklistService
}

// InitDefaultBlacklistService initializes the one process-wide service used
// by proxy hot paths. It does not lazily open SQLite from Contains.
func InitDefaultBlacklistService(legacyIPs []string) (*BlacklistService, LegacyImportStats, error) {
	repo, err := NewDefaultBlacklistRepository()
	if err != nil {
		return nil, LegacyImportStats{}, err
	}
	service, stats, err := NewBlacklistService(repo, legacyIPs)
	if err != nil {
		_ = repo.Close()
		return nil, stats, err
	}

	defaultService.Lock()
	previous := defaultService.service
	defaultService.service = service
	defaultService.Unlock()
	if previous != nil {
		_ = previous.Close()
	}
	return service, stats, nil
}

// GetDefaultBlacklistService returns the initialized process-wide service, or
// nil before startup initialization.
func GetDefaultBlacklistService() *BlacklistService {
	defaultService.RLock()
	service := defaultService.service
	defaultService.RUnlock()
	return service
}

// CloseDefaultBlacklistService clears and closes the process-wide service.
func CloseDefaultBlacklistService() error {
	defaultService.Lock()
	service := defaultService.service
	defaultService.service = nil
	defaultService.Unlock()
	if service == nil {
		return nil
	}
	return service.Close()
}
