package httpapi

import (
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"netflow-plus-v2/internal/catalog"
	"netflow-plus-v2/internal/storage"
	"regexp"
	"strings"
)

const maxSVGBytes = 64 << 10
const svgNamespace = "http://www.w3.org/2000/svg"

var svgElements = map[string]bool{
	"svg": true, "g": true, "path": true, "rect": true, "circle": true,
	"ellipse": true, "line": true, "polyline": true, "polygon": true, "title": true, "desc": true,
}
var svgAttributes = map[string]bool{
	"viewBox": true, "width": true, "height": true, "preserveAspectRatio": true,
	"d": true, "x": true, "y": true, "x1": true, "x2": true, "y1": true, "y2": true,
	"cx": true, "cy": true, "r": true, "rx": true, "ry": true, "points": true,
	"transform": true, "fill": true, "stroke": true, "opacity": true, "fill-opacity": true,
	"fill-rule": true, "stroke-opacity": true, "stroke-width": true, "stroke-linecap": true,
	"stroke-linejoin": true, "stroke-miterlimit": true, "stroke-dasharray": true,
	"stroke-dashoffset": true, "clip-rule": true, "vector-effect": true,
}
var errUnsafeSVG = errors.New("invalid or unsupported SVG")
var svgXMLDeclaration = regexp.MustCompile(`^version\s*=\s*(?:"1\.0"|'1\.0')(?:\s+encoding\s*=\s*(?:"(?i:utf-8)"|'(?i:utf-8)'))?(?:\s+standalone\s*=\s*(?:"(?:yes|no)"|'(?:yes|no)'))?\s*$`)

func validateSVG(content string) error {
	if len(content) == 0 || len(content) > maxSVGBytes {
		return errUnsafeSVG
	}
	decoder := xml.NewDecoder(strings.NewReader(content))
	var stack []string
	nodes := 0
	for {
		offset := decoder.InputOffset()
		token, err := decoder.Token()
		if err == io.EOF && nodes > 0 && len(stack) == 0 {
			return nil
		}
		if err != nil {
			return errUnsafeSVG
		}
		switch value := token.(type) {
		case xml.StartElement:
			name := value.Name.Local
			root := len(stack) == 0
			nodes++
			if nodes > 1024 || len(stack) >= 32 || value.Name.Space != svgNamespace || !svgElements[name] ||
				(root && (name != "svg" || nodes != 1)) || (!root && (name == "svg" || (stack[len(stack)-1] != "svg" && stack[len(stack)-1] != "g"))) {
				return errUnsafeSVG
			}
			seen := make(map[string]bool, len(value.Attr))
			for _, attr := range value.Attr {
				if attr.Name.Space != "" || seen[attr.Name.Local] {
					return errUnsafeSVG
				}
				seen[attr.Name.Local] = true
				if root && attr.Name.Local == "xmlns" && attr.Value == svgNamespace {
					continue
				}
				if !svgAttributes[attr.Name.Local] || !safeSVGAttribute(attr.Value) {
					return errUnsafeSVG
				}
			}
			if root && !seen["xmlns"] {
				return errUnsafeSVG
			}
			stack = append(stack, name)
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) > 0 && (stack[len(stack)-1] == "title" || stack[len(stack)-1] == "desc") {
				continue
			}
			if strings.TrimSpace(string(value)) != "" {
				return errUnsafeSVG
			}
		case xml.ProcInst:
			if offset != 0 || value.Target != "xml" || !svgXMLDeclaration.Match(value.Inst) {
				return errUnsafeSVG
			}
		case xml.Comment:
		default:
			return errUnsafeSVG
		}
	}
}

func safeSVGAttribute(value string) bool {
	if strings.Contains(strings.ToLower(value), "url") {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			strings.ContainsRune(" #.+-%,()\t\r\n", c)) {
			return false
		}
	}
	return true
}

func (s *Server) setAppIcon(w http.ResponseWriter, r *http.Request) {
	if !safeMutation(r) {
		jsonResponse(w, http.StatusForbidden, map[string]string{"error": "请求来源或内容类型无效"})
		return
	}
	var change struct {
		Path  *string `json:"path"`
		SVG   *string `json:"svg"`
		Reset bool    `json:"reset"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 6*maxSVGBytes+1024)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var extra any
	if dec.Decode(&change) != nil || dec.Decode(&extra) != io.EOF ||
		(!change.Reset && change.SVG == nil && change.Path == nil) ||
		(change.SVG != nil && (change.Path != nil || change.Reset)) ||
		(change.Path != nil && (change.Reset || !catalog.ValidIcon(*change.Path))) {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "图标设置格式无效"})
		return
	}
	if change.SVG != nil && validateSVG(*change.SVG) != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "SVG 须在 64 KiB 内，仅支持基础图形与绘制属性"})
		return
	}
	id := r.PathValue("id")
	apps, err := s.allApps(r.Context())
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "应用读取失败"})
		return
	}
	found := false
	for _, app := range apps {
		if app.ID == id {
			found = true
			break
		}
	}
	if !found {
		jsonResponse(w, http.StatusNotFound, map[string]string{"error": "应用不存在"})
		return
	}
	var icon *storage.AppIconOverride
	if !change.Reset {
		icon = &storage.AppIconOverride{}
		if change.SVG != nil {
			icon.SVG = *change.SVG
		} else {
			icon.Path = *change.Path
		}
	}
	if err := s.Store.SaveAppIconOverride(r.Context(), id, icon); err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "图标保存失败"})
		return
	}
	jsonResponse(w, http.StatusOK, map[string]bool{"saved": true})
}

func uploadedIconURL(id, svg string) string {
	digest := sha256.Sum256([]byte(svg))
	return fmt.Sprintf("/api/apps/%s/icon?v=%x", url.PathEscape(id), digest[:8])
}

func (s *Server) appIcon(w http.ResponseWriter, r *http.Request) {
	icons, err := s.Store.AppIconOverrides(r.Context())
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"error": "图标读取失败"})
		return
	}
	icon, ok := icons[r.PathValue("id")]
	if !ok || validateSVG(icon.SVG) != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, icon.SVG)
}
