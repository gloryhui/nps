package file

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeGlobalJSONForTest(t *testing.T, content string) *JsonDb {
	t.Helper()
	runPath := t.TempDir()
	confPath := filepath.Join(runPath, "conf")
	if err := os.MkdirAll(confPath, 0o755); err != nil {
		t.Fatalf("create config directory: %v", err)
	}
	jsonDB := NewJsonDb(runPath)
	if err := os.WriteFile(jsonDB.GlobalFilePath, []byte(content), 0o644); err != nil {
		t.Fatalf("write global.json: %v", err)
	}
	return jsonDB
}

func TestLoadGlobalFromJSONRecordsMalformedJSONError(t *testing.T) {
	jsonDB := writeGlobalJSONForTest(t, `{"BlackIpList": [`)
	jsonDB.LoadGlobalFromJsonFile()

	if jsonDB.Global != nil {
		t.Fatal("Global != nil after malformed global.json")
	}
	err := jsonDB.GetGlobalLoadError()
	if err == nil {
		t.Fatal("GetGlobalLoadError() = nil after malformed global.json")
	}
	if !strings.Contains(err.Error(), "parse global config") || !strings.Contains(err.Error(), "global.json") {
		t.Fatalf("global load error = %q, want parse/global.json context", err)
	}
}

func TestLoadGlobalFromJSONAcceptsValidEmptyJSON(t *testing.T) {
	jsonDB := writeGlobalJSONForTest(t, `{}`)
	jsonDB.LoadGlobalFromJsonFile()

	if err := jsonDB.GetGlobalLoadError(); err != nil {
		t.Fatalf("GetGlobalLoadError() = %v, want nil", err)
	}
	if jsonDB.Global == nil {
		t.Fatal("Global = nil after valid empty global.json")
	}
	if len(jsonDB.Global.BlackIpList) != 0 {
		t.Fatalf("BlackIpList = %#v, want empty", jsonDB.Global.BlackIpList)
	}
}

func TestLoadGlobalFromJSONAllowsMissingFile(t *testing.T) {
	jsonDB := NewJsonDb(t.TempDir())
	jsonDB.LoadGlobalFromJsonFile()

	if err := jsonDB.GetGlobalLoadError(); err != nil {
		t.Fatalf("GetGlobalLoadError() = %v, want nil for missing file", err)
	}
	if jsonDB.Global != nil {
		t.Fatal("Global != nil for missing global.json")
	}
}
