package controllers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"ehang.io/nps/bridge"
	"ehang.io/nps/lib/file"
	"ehang.io/nps/lib/security"
	"ehang.io/nps/server"
	"ehang.io/nps/web"
	beego "github.com/astaxie/beego"
	beegoContext "github.com/astaxie/beego/context"
)

func newGlobalTestController(t *testing.T, method string, params url.Values) (*GlobalController, *httptest.ResponseRecorder) {
	t.Helper()
	target := "/global/index"
	var body *strings.Reader
	if method == http.MethodPost {
		body = strings.NewReader(params.Encode())
	} else {
		body = strings.NewReader("")
	}
	request := httptest.NewRequest(method, target, body)
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	recorder := httptest.NewRecorder()
	ctx := beegoContext.NewContext()
	ctx.Reset(recorder, request)
	controller := &GlobalController{}
	controller.Init(ctx, "GlobalController", "Save", nil)
	controller.CruSession = newBlacklistTestSession(adminSession())
	return controller, recorder
}

func newGlobalTestDB(t *testing.T) *file.DbUtils {
	t.Helper()
	runPath := t.TempDir()
	if err := os.MkdirAll(filepath.Join(runPath, "conf"), 0o755); err != nil {
		t.Fatalf("create global test config directory: %v", err)
	}
	return &file.DbUtils{JsonDb: file.NewJsonDb(runPath)}
}

func setGlobalTestDB(t *testing.T, db *file.DbUtils) {
	t.Helper()
	previous := globalDBProvider
	globalDBProvider = func() *file.DbUtils { return db }
	t.Cleanup(func() { globalDBProvider = previous })
}

func TestGlobalSavePreservesLegacyBlacklistAndIgnoresPostedTextarea(t *testing.T) {
	db := newGlobalTestDB(t)
	db.JsonDb.Global = &file.Glob{
		BlackIpList: []string{"192.0.2.1", "2001:db8::1"},
		ServerUrl:   "old.example.com",
	}
	setGlobalTestDB(t, db)

	controller, _ := newGlobalTestController(t, http.MethodPost, url.Values{
		"serverUrl":         {"new.example.com"},
		"globalBlackIpList": {"203.0.113.99"},
	})
	runBlacklistController(t, controller.Save)

	got := db.GetGlobal()
	if got == nil {
		t.Fatal("GetGlobal() = nil after Save")
	}
	if got.ServerUrl != "new.example.com" {
		t.Fatalf("ServerUrl = %q, want new.example.com", got.ServerUrl)
	}
	if !reflect.DeepEqual(got.BlackIpList, []string{"192.0.2.1", "2001:db8::1"}) {
		t.Fatalf("BlackIpList = %#v, want original legacy entries", got.BlackIpList)
	}
}

func TestGlobalSaveWithNilGlobalCreatesConfigWithoutLegacyEntries(t *testing.T) {
	db := newGlobalTestDB(t)
	setGlobalTestDB(t, db)

	controller, _ := newGlobalTestController(t, http.MethodPost, url.Values{"serverUrl": {"new.example.com"}})
	runBlacklistController(t, controller.Save)

	got := db.GetGlobal()
	if got == nil || got.ServerUrl != "new.example.com" || len(got.BlackIpList) != 0 {
		t.Fatalf("GetGlobal() = %#v, want new URL and empty legacy list", got)
	}
}

func TestGlobalIndexDoesNotExposeLegacyBlacklistTextarea(t *testing.T) {
	db := newGlobalTestDB(t)
	db.JsonDb.Global = &file.Glob{BlackIpList: []string{"192.0.2.1"}, ServerUrl: "example.com"}
	setGlobalTestDB(t, db)
	previousBridge := server.Bridge
	server.Bridge = &bridge.Bridge{}
	t.Cleanup(func() { server.Bridge = previousBridge })

	controller, _ := newGlobalTestController(t, http.MethodGet, nil)
	controller.Init(controller.Ctx, "GlobalController", "Index", nil)
	controller.CruSession = newBlacklistTestSession(adminSession())
	controller.Index()
	if _, ok := controller.Data["globalBlackIpList"]; ok {
		t.Fatal("Global Index still exposes globalBlackIpList")
	}
}

func TestBlacklistIndexRendersWithoutLoadingBlacklistRows(t *testing.T) {
	called := false
	previousServiceProvider := blacklistServiceProvider
	blacklistServiceProvider = func() *security.BlacklistService {
		called = true
		return nil
	}
	t.Cleanup(func() { blacklistServiceProvider = previousServiceProvider })
	previousBridge := server.Bridge
	server.Bridge = &bridge.Bridge{}
	t.Cleanup(func() { server.Bridge = previousBridge })

	controller, recorder := newBlacklistTestController(t, http.MethodGet, "Index", nil, adminSession())
	runBlacklistController(t, controller.Prepare)
	controller.Index()
	if controller.TplName != "blacklist/index.html" {
		t.Fatalf("TplName = %q, want blacklist/index.html", controller.TplName)
	}
	if called {
		t.Fatal("Blacklist Index loaded blacklist service rows")
	}

	web.InitBeegoAssets()
	if err := beego.AddViewPath("views"); err != nil {
		t.Fatalf("AddViewPath() error = %v", err)
	}
	if err := controller.Render(); err != nil {
		t.Fatalf("Blacklist Index Render() error = %v", err)
	}
	if !strings.Contains(recorder.Body.String(), "blacklist_table") {
		t.Fatal("rendered blacklist page does not contain the table")
	}
	page := recorder.Body.String()
	for _, marker := range []string{"escape: true", ".text(", "escapeHtml(", "refreshAfterMutation"} {
		if !strings.Contains(page, marker) {
			t.Fatalf("rendered blacklist page is missing safety/refresh marker %q", marker)
		}
	}
	if strings.Contains(page, "onclick=") {
		t.Fatal("blacklist page uses inline onclick handlers")
	}
	if strings.Contains(page, "location.reload") {
		t.Fatal("blacklist page performs a full page reload after mutations")
	}
}

func TestBlacklistIndexPermissionsAndMethodGuard(t *testing.T) {
	previousBridge := server.Bridge
	server.Bridge = &bridge.Bridge{}
	t.Cleanup(func() { server.Bridge = previousBridge })

	for _, test := range []struct {
		name    string
		session map[interface{}]interface{}
	}{
		{name: "unauthenticated", session: nil},
		{name: "client", session: clientSession()},
	} {
		t.Run(test.name, func(t *testing.T) {
			controller, recorder := newBlacklistTestController(t, http.MethodGet, "Index", nil, test.session)
			runBlacklistController(t, controller.Prepare)
			if recorder.Code >= http.StatusOK && recorder.Code < http.StatusMultipleChoices {
				t.Fatalf("denied Index response status = %d", recorder.Code)
			}
		})
	}

	controller, recorder := newBlacklistTestController(t, http.MethodPost, "Index", nil, adminSession())
	runBlacklistController(t, controller.Prepare)
	runBlacklistController(t, controller.Index)
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST Index status = %d, want %d", recorder.Code, http.StatusMethodNotAllowed)
	}
	response := blacklistResponse(t, recorder)
	if response["code"] != "invalid_request" {
		t.Fatalf("POST Index response = %v, want invalid_request", response)
	}
}
