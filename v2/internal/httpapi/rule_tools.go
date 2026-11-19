package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"netflow-plus-v2/internal/catalog"
	"netflow-plus-v2/internal/storage"
)

func (s *Server) registerRuleTools(m *http.ServeMux) {
	m.HandleFunc("GET /api/rules/export", s.auth(s.exportRules))
	m.HandleFunc("POST /api/rules/import", s.auth(s.importRules))
	m.HandleFunc("PUT /api/apps/{id}/icon", s.auth(s.setAppIcon))
	m.HandleFunc("GET /api/apps/{id}/icon", s.auth(s.appIcon))
	m.HandleFunc("GET /api/apps/icons", s.auth(func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, http.StatusOK, catalog.Icons())
	}))
}

func (s *Server) exportRules(w http.ResponseWriter, r *http.Request) {
	backup, err := s.Store.ExportRuleBackup(r.Context())
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "规则导出失败"})
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="netflow-rules.json"`)
	jsonResponse(w, http.StatusOK, backup)
}

const maxRuleImportBytes = 2 << 20

func (s *Server) importRules(w http.ResponseWriter, r *http.Request) {
	if !safeMutation(r) {
		jsonResponse(w, http.StatusForbidden, map[string]string{"error": "请求来源或内容类型无效"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRuleImportBytes)
	var backup storage.RuleBackup
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var trailing any
	err := dec.Decode(&backup)
	if err == nil {
		err = dec.Decode(&trailing)
	}
	if err != io.EOF || backup.Version == 0 {
		var oversized *http.MaxBytesError
		if errors.As(err, &oversized) {
			jsonResponse(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "规则文件不得超过 2 MiB"})
			return
		}
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "规则文件格式无效"})
		return
	}
	result, err := s.Store.ImportRuleBackup(r.Context(), backup, s.Apps)
	switch {
	case errors.Is(err, storage.ErrAppConflict):
		jsonResponse(w, http.StatusConflict, map[string]string{"error": "文件中的应用编号与现有应用冲突"})
	case errors.Is(err, storage.ErrInvalidRuleBackup):
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "请检查备份版本、应用、域名、匹配方式和优先级"})
	case err != nil:
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "规则导入失败"})
	default:
		jsonResponse(w, http.StatusOK, result)
	}
}
