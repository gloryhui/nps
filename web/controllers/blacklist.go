package controllers

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ehang.io/nps/lib/security"
	"github.com/astaxie/beego/logs"
)

const (
	blacklistDefaultLimit = 50
	blacklistMaxLimit     = 200
)

var blacklistServiceProvider = security.GetDefaultBlacklistService

// BlacklistController exposes administrator-only blacklist management APIs.
// It deliberately depends on BlacklistService rather than Repository so
// mutations keep SQLite and the runtime index consistent.
type BlacklistController struct {
	BaseController
}

type blacklistIPResponse struct {
	ID          int64  `json:"id"`
	IP          string `json:"ip"`
	Source      string `json:"source"`
	Reason      string `json:"reason"`
	Enabled     bool   `json:"enabled"`
	Active      bool   `json:"active"`
	FirstSeenAt int64  `json:"first_seen_at"`
	LastSeenAt  int64  `json:"last_seen_at"`
	ExpireAt    *int64 `json:"expire_at"`
	HitCount    int64  `json:"hit_count"`
	CreatedAt   int64  `json:"created_at"`
	UpdatedAt   int64  `json:"updated_at"`
}

type blacklistStatsResponse struct {
	Total    int64 `json:"total"`
	Enabled  int64 `json:"enabled"`
	Disabled int64 `json:"disabled"`
	Manual   int64 `json:"manual"`
	Import   int64 `json:"import"`
	Auto     int64 `json:"auto"`
	Expired  int64 `json:"expired"`
	Active   int64 `json:"active"`
}

// Prepare preserves the existing auth_key/timestamp/session processing and
// then adds the blacklist-specific administrator check.
func (s *BlacklistController) Prepare() {
	s.BaseController.Prepare()
	isAdmin, ok := s.GetSession("isAdmin").(bool)
	if !ok || !isAdmin {
		s.apiError(http.StatusForbidden, "forbidden", "admin permission required")
	}
}

// Index renders the administrator-only management page. The page itself does
// not load blacklist rows; the browser requests stats and paginated rows from
// the API after rendering.
func (s *BlacklistController) Index() {
	if s.Ctx.Request.Method != http.MethodGet {
		s.apiError(http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
		return
	}
	s.Data["menu"] = "blacklist"
	s.SetInfo("blacklist")
	s.display("blacklist/index")
}

func (s *BlacklistController) List() {
	if !s.requireReadMethod() {
		return
	}
	offset, limit, err := parseOffsetLimit(s.GetString("offset"), s.GetString("limit"))
	if err != nil {
		s.apiError(http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	source, err := validateBlacklistSource(s.GetString("source"))
	if err != nil {
		s.apiError(http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	enabled, err := parseOptionalBool(s.GetString("enabled"), requestParamPresent(s, "enabled"))
	if err != nil {
		s.apiError(http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	ip := strings.TrimSpace(s.GetString("ip"))
	if ip != "" {
		ip, err = security.NormalizeIP(ip)
		if err != nil {
			s.apiError(http.StatusBadRequest, "invalid_ip", "invalid IP")
			return
		}
	}

	service := blacklistServiceProvider()
	if service == nil {
		s.internalError("list")
		return
	}
	result, err := service.ListPage(security.ListOptions{
		Offset:  offset,
		Limit:   limit,
		IP:      ip,
		Source:  source,
		Enabled: enabled,
	})
	if err != nil {
		s.handleBlacklistError("list", err)
		return
	}
	now := time.Now().Unix()
	rows := make([]blacklistIPResponse, 0, len(result.Items))
	for _, item := range result.Items {
		rows = append(rows, newBlacklistIPResponse(item, now))
	}
	s.Data["json"] = map[string]interface{}{"rows": rows, "total": result.Total}
	s.ServeJSON()
	s.StopRun()
}

func (s *BlacklistController) Detail() {
	if !s.requireReadMethod() {
		return
	}
	ip := strings.TrimSpace(s.GetString("ip"))
	if ip == "" {
		s.apiError(http.StatusBadRequest, "invalid_request", "ip is required")
		return
	}
	service := blacklistServiceProvider()
	if service == nil {
		s.internalError("detail")
		return
	}
	item, err := service.GetByIP(ip)
	if err != nil {
		s.handleBlacklistError("detail", err)
		return
	}
	s.apiSuccess(map[string]interface{}{"data": newBlacklistIPResponse(*item, time.Now().Unix())})
}

func (s *BlacklistController) Stats() {
	if !s.requireReadMethod() {
		return
	}
	service := blacklistServiceProvider()
	if service == nil {
		s.internalError("stats")
		return
	}
	stats, err := service.Stats(time.Now().Unix())
	if err != nil {
		s.handleBlacklistError("stats", err)
		return
	}
	s.apiSuccess(map[string]interface{}{"data": blacklistStatsResponse{
		Total: stats.Total, Enabled: stats.Enabled, Disabled: stats.Disabled,
		Manual: stats.Manual, Import: stats.Import, Auto: stats.Auto,
		Expired: stats.Expired, Active: stats.Active,
	}})
}

func (s *BlacklistController) Add() {
	if !s.requirePostMethod() {
		return
	}
	ip := strings.TrimSpace(s.GetString("ip"))
	if ip == "" {
		s.apiError(http.StatusBadRequest, "invalid_ip", "invalid IP")
		return
	}
	enabled, err := parseOptionalBool(s.GetString("enabled"), requestParamPresent(s, "enabled"))
	if err != nil {
		s.apiError(http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	expireAt, err := parseBlacklistExpireAt(s.GetString("expire_at"))
	if err != nil {
		s.apiError(http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	service := blacklistServiceProvider()
	if service == nil {
		s.internalError("add")
		return
	}
	err = service.Add(security.BlacklistIPInput{
		IP: ip, Source: "manual", Reason: s.GetString("reason"),
		Enabled: enabled, ExpireAt: expireAt,
	})
	if err != nil {
		s.handleBlacklistError("add", err)
		return
	}
	normalized, err := security.NormalizeIP(ip)
	if err != nil {
		s.handleBlacklistError("add readback", err)
		return
	}
	item, err := service.GetByIP(normalized)
	if err != nil {
		s.handleBlacklistError("add readback", err)
		return
	}
	s.apiSuccess(map[string]interface{}{"data": newBlacklistIPResponse(*item, time.Now().Unix())})
}

func (s *BlacklistController) Delete() {
	if !s.requirePostMethod() {
		return
	}
	s.mutateIP("delete", func(service *security.BlacklistService, ip string) error {
		return service.Delete(ip)
	})
}

func (s *BlacklistController) Enable() {
	if !s.requirePostMethod() {
		return
	}
	s.mutateIP("enable", func(service *security.BlacklistService, ip string) error {
		return service.Enable(ip)
	})
}

func (s *BlacklistController) Disable() {
	if !s.requirePostMethod() {
		return
	}
	s.mutateIP("disable", func(service *security.BlacklistService, ip string) error {
		return service.Disable(ip)
	})
}

func (s *BlacklistController) mutateIP(operation string, mutation func(*security.BlacklistService, string) error) {
	ip := strings.TrimSpace(s.GetString("ip"))
	if ip == "" {
		s.apiError(http.StatusBadRequest, "invalid_request", "ip is required")
		return
	}
	service := blacklistServiceProvider()
	if service == nil {
		s.internalError(operation)
		return
	}
	if err := mutation(service, ip); err != nil {
		s.handleBlacklistError(operation, err)
		return
	}
	s.apiSuccess(nil)
}

func (s *BlacklistController) requireReadMethod() bool {
	if s.Ctx.Request.Method != http.MethodGet && s.Ctx.Request.Method != http.MethodPost {
		s.apiError(http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
		return false
	}
	return true
}

func (s *BlacklistController) requirePostMethod() bool {
	if s.Ctx.Request.Method != http.MethodPost {
		s.apiError(http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
		return false
	}
	return true
}

func (s *BlacklistController) apiSuccess(data map[string]interface{}) {
	payload := map[string]interface{}{"status": 1}
	for key, value := range data {
		payload[key] = value
	}
	s.Data["json"] = payload
	s.ServeJSON()
	s.StopRun()
}

func (s *BlacklistController) apiError(status int, code, message string) {
	s.Ctx.ResponseWriter.WriteHeader(status)
	s.Data["json"] = map[string]interface{}{"status": 0, "code": code, "msg": message}
	s.ServeJSON()
	s.StopRun()
}

func (s *BlacklistController) internalError(operation string) {
	logs.Error("blacklist %s: service is not initialized", operation)
	s.apiError(http.StatusInternalServerError, "internal_error", "blacklist operation failed")
}

func (s *BlacklistController) handleBlacklistError(operation string, err error) {
	switch {
	case errors.Is(err, security.ErrInvalidIP):
		s.apiError(http.StatusBadRequest, "invalid_ip", "invalid IP")
	case errors.Is(err, security.ErrDuplicateIP):
		s.apiError(http.StatusConflict, "duplicate_ip", "blacklist IP already exists")
	case errors.Is(err, security.ErrNotFound):
		s.apiError(http.StatusNotFound, "not_found", "blacklist IP not found")
	default:
		logs.Error("blacklist %s failed: %v", operation, err)
		s.apiError(http.StatusInternalServerError, "internal_error", "blacklist operation failed")
	}
}

func newBlacklistIPResponse(item security.BlacklistIP, now int64) blacklistIPResponse {
	active := item.Enabled && (item.ExpireAt == nil || *item.ExpireAt > now)
	return blacklistIPResponse{
		ID: item.ID, IP: item.IP, Source: item.Source, Reason: item.Reason,
		Enabled: item.Enabled, Active: active, FirstSeenAt: item.FirstSeenAt,
		LastSeenAt: item.LastSeenAt, ExpireAt: item.ExpireAt, HitCount: item.HitCount,
		CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt,
	}
}

func requestParamPresent(s *BlacklistController, key string) bool {
	_ = s.Ctx.Request.ParseForm()
	if _, ok := s.Ctx.Request.URL.Query()[key]; ok {
		return true
	}
	_, ok := s.Ctx.Request.Form[key]
	return ok
}

func parseOffsetLimit(rawOffset, rawLimit string) (int, int, error) {
	offset := 0
	if strings.TrimSpace(rawOffset) != "" {
		parsed, err := strconv.Atoi(strings.TrimSpace(rawOffset))
		if err != nil || parsed < 0 {
			return 0, 0, errors.New("invalid offset")
		}
		offset = parsed
	}
	limit := blacklistDefaultLimit
	if strings.TrimSpace(rawLimit) != "" {
		parsed, err := strconv.Atoi(strings.TrimSpace(rawLimit))
		if err != nil || parsed < 0 || parsed > blacklistMaxLimit {
			return 0, 0, errors.New("invalid limit")
		}
		if parsed != 0 {
			limit = parsed
		}
	}
	return offset, limit, nil
}

func validateBlacklistSource(raw string) (string, error) {
	source := strings.TrimSpace(raw)
	switch source {
	case "", "manual", "import", "auto":
		return source, nil
	default:
		return "", errors.New("invalid source")
	}
}

func parseOptionalBool(raw string, present bool) (*bool, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if !present || value == "" {
		return nil, nil
	}
	var parsed bool
	switch value {
	case "true", "1":
		parsed = true
	case "false", "0":
		parsed = false
	default:
		return nil, errors.New("invalid enabled")
	}
	return &parsed, nil
}

func parseBlacklistExpireAt(raw string) (*int64, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, nil
	}
	if parsed, err := strconv.ParseInt(value, 10, 64); err == nil {
		if parsed < 0 {
			return nil, errors.New("expire_at must not be negative")
		}
		return &parsed, nil
	}
	parsedTime, ok := ParseExpireTime(value)
	if !ok {
		return nil, errors.New("invalid expire_at")
	}
	parsed := parsedTime.Unix()
	return &parsed, nil
}
