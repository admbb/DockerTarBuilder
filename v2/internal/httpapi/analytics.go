package httpapi

import (
	"context"
	"net/http"
	"net/netip"
	"strconv"
	"time"
)

const maxCustomRange = 30 * 24 * time.Hour

// analytics validates custom periods before the endpoint computes time bounds.
func (s *Server) analytics(h http.HandlerFunc) http.HandlerFunc {
	return s.auth(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("range") == "custom" || q.Has("from_ms") || q.Has("to_ms") {
			from, fromErr := strconv.ParseInt(q.Get("from_ms"), 10, 64)
			to, toErr := strconv.ParseInt(q.Get("to_ms"), 10, 64)
			if fromErr != nil || toErr != nil || from < 0 || to <= from || to > time.Now().UnixMilli() || to-from > maxCustomRange.Milliseconds() {
				jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "自定义时间范围需要有效的起止时间，最多 30 天，且不能晚于当前时间"})
				return
			}
		}
		h(w, r)
	})
}

func (s *Server) trafficDevices(w http.ResponseWriter, r *http.Request) {
	if !s.FlowEnabled {
		jsonResponse(w, http.StatusUnprocessableEntity, map[string]string{"error": "独立 IPFIX 采集器未启用"})
		return
	}
	_, from, to := rangeMillis(r)
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	devices, err := s.Store.ReceivedTrafficDevices(ctx, from, to)
	if err != nil {
		jsonResponse(w, http.StatusServiceUnavailable, map[string]string{"error": "设备流量暂不可用"})
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{
		"items": devices, "from_ms": from, "to_ms": to, "coverage_complete": false,
	})
}

func trafficClient(w http.ResponseWriter, r *http.Request) (string, bool) {
	value := r.URL.Query().Get("device")
	if value == "" {
		return "", true
	}
	ip, err := netip.ParseAddr(value)
	if err != nil || ip.Zone() != "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "设备筛选需要有效的 IP 地址"})
		return "", false
	}
	return ip.Unmap().String(), true
}
