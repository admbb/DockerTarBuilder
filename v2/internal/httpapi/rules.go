package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"netflow-plus-v2/internal/catalog"
	"netflow-plus-v2/internal/correlation"
	"netflow-plus-v2/internal/storage"
	"strconv"
	"strings"
)

func (s *Server) allApps(ctx context.Context) ([]catalog.App, error) {
	extra, err := s.Store.CustomApps(ctx)
	if err != nil {
		return nil, err
	}
	overrides, err := s.Store.AppIconOverrides(ctx)
	if err != nil {
		return nil, err
	}
	customIDs := make(map[string]bool, len(extra))
	for _, app := range extra {
		customIDs[app.ID] = true
	}
	apps := make([]catalog.App, 0, len(s.Apps)+len(extra))
	for _, app := range s.Apps {
		if !customIDs[app.ID] {
			apps = append(apps, app)
		}
	}
	apps = append(apps, extra...)
	for i, app := range apps {
		if icon, ok := overrides[app.ID]; ok {
			if icon.SVG != "" {
				apps[i].Icon = uploadedIconURL(app.ID, icon.SVG)
			} else if catalog.ValidIcon(icon.Path) {
				apps[i].Icon = icon.Path
			}
		}
	}
	return apps, nil
}
func (s *Server) createApp(w http.ResponseWriter, r *http.Request) {
	if !safeMutation(r) {
		jsonResponse(w, 403, map[string]string{"error": "请求来源或内容类型无效"})
		return
	}
	var a catalog.App
	dec := json.NewDecoder(io.LimitReader(r.Body, 8193))
	dec.DisallowUnknownFields()
	if dec.Decode(&a) != nil {
		jsonResponse(w, 400, map[string]string{"error": "应用格式无效"})
		return
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		jsonResponse(w, 400, map[string]string{"error": "应用格式无效"})
		return
	}
	a.ID = strings.TrimSpace(a.ID)
	a.Name = strings.TrimSpace(a.Name)
	a.Category = strings.TrimSpace(a.Category)
	apps, err := s.allApps(r.Context())
	if err != nil {
		jsonResponse(w, 500, map[string]string{"error": "应用读取失败"})
		return
	}
	for _, existing := range apps {
		if existing.ID == a.ID {
			jsonResponse(w, 409, map[string]string{"error": "应用编号已存在"})
			return
		}
	}
	if err := s.Store.SaveCustomApp(r.Context(), a); err != nil {
		if errors.Is(err, storage.ErrAppConflict) {
			jsonResponse(w, 409, map[string]string{"error": "应用编号已存在"})
			return
		}
		jsonResponse(w, 400, map[string]string{"error": "请检查应用编号、名称和分类"})
		return
	}
	jsonResponse(w, 200, a)
}

func (s *Server) effectiveRules(ctx context.Context) ([]correlation.Rule, error) {
	user, err := s.Store.UserRules(ctx)
	if err != nil {
		return nil, err
	}
	customApps, err := s.Store.CustomApps(ctx)
	if err != nil {
		return nil, err
	}
	customIDs := make(map[string]bool, len(customApps))
	for _, app := range customApps {
		customIDs[app.ID] = true
	}
	rules := make([]correlation.Rule, 0, len(s.Rules)+len(user))
	for _, rule := range s.Rules {
		// Preserve custom IDs created before a built-in application used the same ID.
		if !customIDs[rule.AppID] {
			rules = append(rules, rule)
		}
	}
	for _, v := range user {
		rules = append(rules, correlation.Rule{Domain: v.Domain, AppID: v.AppID, Exact: v.Match == "exact", Exclude: v.Exclude, Priority: v.Priority})
	}
	return rules, nil
}
func (s *Server) listRules(w http.ResponseWriter, r *http.Request) {
	v, err := s.Store.UserRules(r.Context())
	if err != nil {
		jsonResponse(w, 500, map[string]string{"error": "规则读取失败"})
		return
	}
	jsonResponse(w, 200, map[string]any{"items": v, "builtin_count": len(s.Rules)})
}
func safeMutation(r *http.Request) bool {
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		if err != nil || !strings.EqualFold(u.Host, r.Host) || (u.Scheme != "http" && u.Scheme != "https") {
			return false
		}
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mediaType == "application/json"
}
func (s *Server) writeRule(w http.ResponseWriter, r *http.Request) {
	if !safeMutation(r) {
		jsonResponse(w, 403, map[string]string{"error": "请求来源或内容类型无效"})
		return
	}
	var v storage.UserRule
	dec := json.NewDecoder(io.LimitReader(r.Body, 8193))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		jsonResponse(w, 400, map[string]string{"error": "规则格式无效"})
		return
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		jsonResponse(w, 400, map[string]string{"error": "规则格式无效"})
		return
	}
	if r.Method == "PUT" {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil || id <= 0 {
			jsonResponse(w, 400, map[string]string{"error": "规则编号无效"})
			return
		}
		v.ID = id
	} else {
		v.ID = 0
	}
	if !v.Exclude {
		found := false
		apps, err := s.allApps(r.Context())
		if err != nil {
			jsonResponse(w, 500, map[string]string{"error": "应用读取失败"})
			return
		}
		for _, a := range apps {
			if a.ID == v.AppID {
				found = true
				break
			}
		}
		if !found {
			jsonResponse(w, 400, map[string]string{"error": "应用不存在"})
			return
		}
	}
	saved, err := s.Store.SaveUserRule(r.Context(), v)
	if err != nil {
		code := 400
		if errors.Is(err, sql.ErrNoRows) {
			code = 404
		}
		jsonResponse(w, code, map[string]string{"error": "规则保存失败，请检查域名和优先级"})
		return
	}
	jsonResponse(w, 200, saved)
}
func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request) {
	if !safeMutation(r) {
		jsonResponse(w, 403, map[string]string{"error": "请求来源或内容类型无效"})
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		jsonResponse(w, 400, map[string]string{"error": "规则编号无效"})
		return
	}
	if err = s.Store.DeleteUserRule(r.Context(), id); err != nil {
		code := 500
		if errors.Is(err, sql.ErrNoRows) {
			code = 404
		}
		jsonResponse(w, code, map[string]string{"error": "规则删除失败"})
		return
	}
	jsonResponse(w, 200, map[string]bool{"deleted": true})
}
