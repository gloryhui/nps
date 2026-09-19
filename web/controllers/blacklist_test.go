package controllers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ehang.io/nps/lib/crypt"
	"ehang.io/nps/lib/security"
	beego "github.com/astaxie/beego"
	beegoContext "github.com/astaxie/beego/context"
)

type blacklistTestSession struct {
	mu     sync.RWMutex
	values map[interface{}]interface{}
}

func (s *blacklistTestSession) Set(key, value interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[key] = value
	return nil
}

func (s *blacklistTestSession) Get(key interface{}) interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.values[key]
}

func (s *blacklistTestSession) Delete(key interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.values, key)
	return nil
}

func (s *blacklistTestSession) SessionID() string { return "blacklist-controller-test" }

func (s *blacklistTestSession) SessionRelease(http.ResponseWriter) {}

func (s *blacklistTestSession) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values = make(map[interface{}]interface{})
	return nil
}

func newBlacklistTestSession(values map[interface{}]interface{}) *blacklistTestSession {
	if values == nil {
		values = make(map[interface{}]interface{})
	}
	return &blacklistTestSession{values: values}
}

func newBlacklistTestController(t *testing.T, method, action string, params url.Values, sessionValues map[interface{}]interface{}) (*BlacklistController, *httptest.ResponseRecorder) {
	t.Helper()
	target := "/blacklist/" + strings.ToLower(action)
	var body io.Reader
	if method == http.MethodPost {
		body = strings.NewReader(params.Encode())
	} else if encoded := params.Encode(); encoded != "" {
		target += "?" + encoded
	}
	request := httptest.NewRequest(method, target, body)
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	recorder := httptest.NewRecorder()
	ctx := beegoContext.NewContext()
	ctx.Reset(recorder, request)
	controller := &BlacklistController{}
	controller.Init(ctx, "BlacklistController", action, nil)
	controller.CruSession = newBlacklistTestSession(sessionValues)
	return controller, recorder
}

func runBlacklistController(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil && recovered != beego.ErrAbort {
			t.Fatalf("controller panicked: %v", recovered)
		}
	}()
	fn()
}

func setBlacklistTestService(t *testing.T, service *security.BlacklistService) {
	t.Helper()
	previous := blacklistServiceProvider
	blacklistServiceProvider = func() *security.BlacklistService { return service }
	t.Cleanup(func() { blacklistServiceProvider = previous })
}

func newBlacklistTestService(t *testing.T) *security.BlacklistService {
	t.Helper()
	repository, err := security.NewBlacklistRepository(filepath.Join(t.TempDir(), "blacklist.db"))
	if err != nil {
		t.Fatalf("NewBlacklistRepository() error = %v", err)
	}
	service, _, err := security.NewBlacklistService(repository, nil)
	if err != nil {
		_ = repository.Close()
		t.Fatalf("NewBlacklistService() error = %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })
	return service
}

func blacklistResponse(t *testing.T, recorder *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var response map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("response JSON = %q, error = %v", recorder.Body.String(), err)
	}
	return response
}

func invokeBlacklistAction(t *testing.T, method, action string, params url.Values, sessionValues map[interface{}]interface{}) (*httptest.ResponseRecorder, map[string]interface{}) {
	t.Helper()
	controller, recorder := newBlacklistTestController(t, method, action, params, sessionValues)
	switch action {
	case "List":
		runBlacklistController(t, controller.List)
	case "Detail":
		runBlacklistController(t, controller.Detail)
	case "Stats":
		runBlacklistController(t, controller.Stats)
	case "Add":
		runBlacklistController(t, controller.Add)
	case "Delete":
		runBlacklistController(t, controller.Delete)
	case "Enable":
		runBlacklistController(t, controller.Enable)
	case "Disable":
		runBlacklistController(t, controller.Disable)
	default:
		t.Fatalf("unknown blacklist action %q", action)
	}
	return recorder, blacklistResponse(t, recorder)
}

func adminSession() map[interface{}]interface{} {
	return map[interface{}]interface{}{"auth": true, "isAdmin": true}
}

func clientSession() map[interface{}]interface{} {
	return map[interface{}]interface{}{"auth": true, "isAdmin": false, "clientId": 1}
}

func TestBlacklistControllerParameterParsers(t *testing.T) {
	t.Run("offset and limit", func(t *testing.T) {
		tests := []struct {
			name                  string
			offset, limit         string
			wantOffset, wantLimit int
			wantErr               bool
		}{
			{name: "defaults", wantLimit: blacklistDefaultLimit},
			{name: "zero limit uses default", limit: "0", wantLimit: blacklistDefaultLimit},
			{name: "explicit values", offset: "2", limit: "200", wantOffset: 2, wantLimit: 200},
			{name: "negative offset", offset: "-1", wantErr: true},
			{name: "invalid offset", offset: "abc", wantErr: true},
			{name: "negative limit", limit: "-1", wantErr: true},
			{name: "too large limit", limit: "201", wantErr: true},
			{name: "invalid limit", limit: "abc", wantErr: true},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				offset, limit, err := parseOffsetLimit(test.offset, test.limit)
				if (err != nil) != test.wantErr {
					t.Fatalf("parseOffsetLimit() error = %v, wantErr = %t", err, test.wantErr)
				}
				if !test.wantErr && (offset != test.wantOffset || limit != test.wantLimit) {
					t.Fatalf("parseOffsetLimit() = (%d, %d), want (%d, %d)", offset, limit, test.wantOffset, test.wantLimit)
				}
			})
		}
	})

	t.Run("enabled", func(t *testing.T) {
		tests := []struct {
			raw     string
			present bool
			want    *bool
			bad     bool
		}{
			{raw: "", want: nil},
			{raw: "", present: true, want: nil},
			{raw: "true", present: true, want: boolPointer(true)},
			{raw: "1", present: true, want: boolPointer(true)},
			{raw: "false", present: true, want: boolPointer(false)},
			{raw: "0", present: true, want: boolPointer(false)},
			{raw: "abc", present: true, bad: true},
		}
		for _, test := range tests {
			got, err := parseOptionalBool(test.raw, test.present)
			if (err != nil) != test.bad {
				t.Fatalf("parseOptionalBool(%q, %t) error = %v, want bad = %t", test.raw, test.present, err, test.bad)
			}
			if !test.bad && !sameOptionalBool(got, test.want) {
				t.Fatalf("parseOptionalBool(%q, %t) = %v, want %v", test.raw, test.present, got, test.want)
			}
		}
	})

	for _, source := range []string{"", "manual", "import", "auto"} {
		got, err := validateBlacklistSource(source)
		if err != nil || got != source {
			t.Errorf("validateBlacklistSource(%q) = (%q, %v)", source, got, err)
		}
	}
	if _, err := validateBlacklistSource("other"); err == nil {
		t.Error("validateBlacklistSource(other) error = nil")
	}

	date := "2030-01-02 03:04"
	expectedDate := time.Date(2030, time.January, 2, 3, 4, 0, 0, time.Local).Unix()
	for _, test := range []struct {
		raw     string
		want    *int64
		wantErr bool
	}{
		{raw: "", want: nil},
		{raw: "0", want: int64Pointer(0)},
		{raw: "1700000000", want: int64Pointer(1700000000)},
		{raw: date, want: int64Pointer(expectedDate)},
		{raw: "-1", wantErr: true},
		{raw: "2026-99-99 abc", wantErr: true},
	} {
		got, err := parseBlacklistExpireAt(test.raw)
		if (err != nil) != test.wantErr {
			t.Errorf("parseBlacklistExpireAt(%q) error = %v, wantErr = %t", test.raw, err, test.wantErr)
		}
		if !test.wantErr && !sameOptionalInt64(got, test.want) {
			t.Errorf("parseBlacklistExpireAt(%q) = %v, want %v", test.raw, got, test.want)
		}
	}
}

func boolPointer(value bool) *bool { return &value }

func int64Pointer(value int64) *int64 { return &value }

func sameOptionalBool(left, right *bool) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func sameOptionalInt64(left, right *int64) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func TestBlacklistControllerPermissionsForListAndAdd(t *testing.T) {
	service := newBlacklistTestService(t)
	setBlacklistTestService(t, service)

	tests := []struct {
		name    string
		session map[interface{}]interface{}
		allow   bool
	}{
		{name: "unauthenticated", session: nil},
		{name: "client", session: clientSession()},
		{name: "admin", session: adminSession(), allow: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			listController, listRecorder := newBlacklistTestController(t, http.MethodGet, "List", nil, test.session)
			runBlacklistController(t, listController.Prepare)
			if test.allow {
				runBlacklistController(t, listController.List)
				listResponse := blacklistResponse(t, listRecorder)
				if listRecorder.Code != http.StatusOK || listResponse["total"] != float64(0) {
					t.Fatalf("admin List response = (%d, %s)", listRecorder.Code, listRecorder.Body.String())
				}
			} else if listRecorder.Code >= http.StatusOK && listRecorder.Code < http.StatusMultipleChoices {
				t.Fatalf("denied List response status = %d", listRecorder.Code)
			}

			addController, addRecorder := newBlacklistTestController(t, http.MethodPost, "Add", url.Values{
				"ip": {"198.51.100.240"},
			}, test.session)
			runBlacklistController(t, addController.Prepare)
			if test.allow {
				runBlacklistController(t, addController.Add)
				if addRecorder.Code != http.StatusOK || blacklistResponse(t, addRecorder)["status"] != float64(1) {
					t.Fatalf("admin Add response = (%d, %s)", addRecorder.Code, addRecorder.Body.String())
				}
			} else if addRecorder.Code >= http.StatusOK && addRecorder.Code < http.StatusMultipleChoices {
				t.Fatalf("denied Add response status = %d", addRecorder.Code)
			}
		})
	}
}

func TestBlacklistControllerAuthKeyTimestampAllowsAdmin(t *testing.T) {
	service := newBlacklistTestService(t)
	setBlacklistTestService(t, service)

	const authKey = "blacklist-controller-test-key"
	previousAuthKey := beego.AppConfig.String("auth_key")
	if err := beego.AppConfig.Set("auth_key", authKey); err != nil {
		t.Fatalf("set auth_key: %v", err)
	}
	t.Cleanup(func() { _ = beego.AppConfig.Set("auth_key", previousAuthKey) })

	timestamp := time.Now().Unix()
	timestampValue := strconv.FormatInt(timestamp, 10)
	controller, recorder := newBlacklistTestController(t, http.MethodGet, "List", url.Values{
		"auth_key":  {crypt.Md5(authKey + timestampValue)},
		"timestamp": {timestampValue},
	}, nil)
	runBlacklistController(t, controller.Prepare)
	runBlacklistController(t, controller.List)
	if recorder.Code != http.StatusOK {
		t.Fatalf("auth_key List status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if response := blacklistResponse(t, recorder); response["total"] != float64(0) {
		t.Fatalf("auth_key List response = %v", response)
	}
}

func TestBlacklistControllerMutationsAndMethodGuards(t *testing.T) {
	service := newBlacklistTestService(t)
	setBlacklistTestService(t, service)

	add := func(params url.Values) map[string]interface{} {
		_, response := invokeBlacklistAction(t, http.MethodPost, "Add", params, adminSession())
		return response
	}
	if response := add(url.Values{"ip": {"198.51.100.1"}}); response["status"] != float64(1) {
		t.Fatalf("Add IPv4 response = %v", response)
	}
	if response := add(url.Values{"ip": {"2001:db8::1"}}); response["status"] != float64(1) {
		t.Fatalf("Add IPv6 response = %v", response)
	}
	if response := add(url.Values{"ip": {"198.51.100.1"}}); response["code"] != "duplicate_ip" {
		t.Fatalf("duplicate Add response = %v", response)
	}
	if response := add(url.Values{"ip": {"not-an-ip"}}); response["code"] != "invalid_ip" {
		t.Fatalf("invalid Add response = %v", response)
	}
	if response := add(url.Values{"ip": {"198.51.100.2"}, "enabled": {"false"}}); response["status"] != float64(1) {
		t.Fatalf("disabled Add response = %v", response)
	}
	if entry, err := service.GetByIP("198.51.100.2"); err != nil || entry.Enabled {
		t.Fatalf("disabled Add record = %#v, error = %v", entry, err)
	}
	if response := add(url.Values{"ip": {"198.51.100.3"}, "expire_at": {"0"}}); response["status"] != float64(1) {
		t.Fatalf("expired Add response = %v", response)
	}
	if entry, err := service.GetByIP("198.51.100.3"); err != nil || !entry.Enabled || service.Contains("198.51.100.3") {
		t.Fatalf("expired Add record = %#v, contains = %t, error = %v", entry, service.Contains("198.51.100.3"), err)
	}
	if response := add(url.Values{"ip": {"198.51.100.4"}, "expire_at": {"not-a-date"}}); response["code"] != "invalid_request" {
		t.Fatalf("invalid expire_at response = %v", response)
	}
	if _, err := service.GetByIP("198.51.100.4"); !errors.Is(err, security.ErrNotFound) {
		t.Fatalf("invalid expire_at record error = %v", err)
	}

	if response := invokeMutation(t, http.MethodPost, "Disable", "198.51.100.1"); response["status"] != float64(1) {
		t.Fatalf("Disable response = %v", response)
	}
	if service.Contains("198.51.100.1") {
		t.Fatal("disabled active IP remains in runtime index")
	}
	if response := invokeMutation(t, http.MethodPost, "Enable", "198.51.100.1"); response["status"] != float64(1) {
		t.Fatalf("Enable response = %v", response)
	}
	if !service.Contains("198.51.100.1") {
		t.Fatal("enabled active IP missing from runtime index")
	}
	if response := invokeMutation(t, http.MethodPost, "Enable", "198.51.100.3"); response["status"] != float64(1) {
		t.Fatalf("Enable expired response = %v", response)
	}
	if entry, err := service.GetByIP("198.51.100.3"); err != nil || !entry.Enabled || service.Contains("198.51.100.3") {
		t.Fatalf("enabled expired record = %#v, contains = %t, error = %v", entry, service.Contains("198.51.100.3"), err)
	}
	if response := invokeMutation(t, http.MethodPost, "Delete", "198.51.100.2"); response["status"] != float64(1) {
		t.Fatalf("Delete response = %v", response)
	}
	if _, err := service.GetByIP("198.51.100.2"); !errors.Is(err, security.ErrNotFound) {
		t.Fatalf("deleted record error = %v", err)
	}
	if response := invokeMutation(t, http.MethodPost, "Delete", "198.51.100.2"); response["code"] != "not_found" {
		t.Fatalf("Delete missing response = %v", response)
	}

	for _, test := range []struct {
		action string
		ip     string
	}{
		{action: "Add", ip: "198.51.100.10"},
		{action: "Delete", ip: "198.51.100.1"},
		{action: "Enable", ip: "198.51.100.3"},
		{action: "Disable", ip: "198.51.100.1"},
	} {
		before, err := service.GetByIP(test.ip)
		recorder, response := invokeBlacklistAction(t, http.MethodGet, test.action, url.Values{"ip": {test.ip}}, adminSession())
		if recorder.Code != http.StatusMethodNotAllowed || response["code"] != "invalid_request" {
			t.Fatalf("GET %s response = (%d, %v)", test.action, recorder.Code, response)
		}
		after, afterErr := service.GetByIP(test.ip)
		if (err == nil) != (afterErr == nil) || (before != nil && (before.Enabled != after.Enabled || before.IP != after.IP)) {
			t.Fatalf("GET %s changed record: before=%#v err=%v after=%#v err=%v", test.action, before, err, after, afterErr)
		}
	}
}

func invokeMutation(t *testing.T, method, action, ip string) map[string]interface{} {
	_, response := invokeBlacklistAction(t, method, action, url.Values{"ip": {ip}}, adminSession())
	return response
}

func TestBlacklistControllerListAndDatabaseErrorResponses(t *testing.T) {
	service := newBlacklistTestService(t)
	setBlacklistTestService(t, service)
	for _, ip := range []string{"198.51.100.20", "198.51.100.21", "198.51.100.22"} {
		if err := service.Add(security.BlacklistIPInput{IP: ip}); err != nil {
			t.Fatalf("service.Add(%q) error = %v", ip, err)
		}
	}
	recorder, response := invokeBlacklistAction(t, http.MethodGet, "List", url.Values{
		"offset": {"0"}, "limit": {"2"}, "source": {"manual"}, "enabled": {"true"},
	}, adminSession())
	if recorder.Code != http.StatusOK || response["status"] != nil {
		t.Fatalf("List response = (%d, %v)", recorder.Code, response)
	}
	rows, ok := response["rows"].([]interface{})
	if !ok || len(rows) != 2 || response["total"] != float64(3) {
		t.Fatalf("List rows/total = (%v, %v)", response["rows"], response["total"])
	}

	if err := service.Close(); err != nil {
		t.Fatalf("service.Close() error = %v", err)
	}
	recorder, response = invokeBlacklistAction(t, http.MethodPost, "Add", url.Values{"ip": {"198.51.100.30"}}, adminSession())
	if recorder.Code != http.StatusInternalServerError || response["status"] != float64(0) || response["code"] != "internal_error" {
		t.Fatalf("DB error response = (%d, %v)", recorder.Code, response)
	}
	if strings.Contains(recorder.Body.String(), "database is closed") || strings.Contains(recorder.Body.String(), "blacklist.db") {
		t.Fatalf("DB error leaked internals: %s", recorder.Body.String())
	}
}

func TestBlacklistControllerActiveDTO(t *testing.T) {
	expired := int64(100)
	active := newBlacklistIPResponse(security.BlacklistIP{IP: "192.0.2.1", Enabled: true, ExpireAt: &expired}, 100)
	if active.Active {
		t.Fatal("record expiring at request time marked active")
	}
	if got := newBlacklistIPResponse(security.BlacklistIP{IP: "192.0.2.2", Enabled: false}, time.Now().Unix()); got.Active {
		t.Fatal("disabled record marked active")
	}
}
