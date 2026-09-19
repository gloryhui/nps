package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ehang.io/nps/lib/file"
	"ehang.io/nps/lib/security"
)

func TestLoadLegacyBlacklistRejectsMalformedGlobalBeforeMigration(t *testing.T) {
	runPath := t.TempDir()
	confPath := filepath.Join(runPath, "conf")
	if err := os.MkdirAll(confPath, 0o755); err != nil {
		t.Fatalf("create config directory: %v", err)
	}
	jsonDB := file.NewJsonDb(runPath)
	if err := os.WriteFile(jsonDB.GlobalFilePath, []byte(`{"BlackIpList": [`), 0o644); err != nil {
		t.Fatalf("write malformed global.json: %v", err)
	}
	jsonDB.LoadGlobalFromJsonFile()
	db := &file.DbUtils{JsonDb: jsonDB}

	legacyIPs, err := loadLegacyBlacklist(db)
	if err == nil {
		t.Fatal("loadLegacyBlacklist() = nil error for malformed global.json")
	}
	if legacyIPs != nil {
		t.Fatalf("legacy IPs = %#v, want nil on load failure", legacyIPs)
	}
	if !strings.Contains(err.Error(), "load legacy global config for blacklist migration") {
		t.Fatalf("loadLegacyBlacklist() error = %q, want startup migration context", err)
	}

	repository, err := security.NewBlacklistRepository(security.BlacklistDBPath(runPath))
	if err != nil {
		t.Fatalf("open blacklist repository: %v", err)
	}
	defer repository.Close()
	if _, exists, err := repository.GetMeta("legacy_global_blacklist_imported"); err != nil {
		t.Fatalf("read migration marker: %v", err)
	} else if exists {
		t.Fatal("migration marker exists although legacy global load failed")
	}
}
