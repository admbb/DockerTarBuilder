// Package oxidns reads the documented OxiDNS query recorder endpoint only.
package oxidns

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Question struct {
	Name  string `json:"name"`
	QType string `json:"qtype"`
}
type Answer struct {
	Name string `json:"name"`
	Type string `json:"rr_type"`
	TTL  uint32 `json:"ttl"`
	Data string `json:"payload_text"`
}
type Record struct {
	ID          int64      `json:"id"`
	CreatedAtMS int64      `json:"created_at_ms"`
	ClientIP    string     `json:"client_ip"`
	Questions   []Question `json:"questions_json"`
	Answers     []Answer   `json:"answers_json"`
	HasResponse bool       `json:"has_response"`
	RCode       string     `json:"rcode"`
}
type Page struct {
	OK         bool     `json:"ok"`
	NextCursor string   `json:"next_cursor"`
	Records    []Record `json:"records"`
}
type Client struct {
	base                    *url.URL
	tag, username, password string
	http                    *http.Client
}

func NewClient(baseURL, tag, username, password string) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("invalid OxiDNS URL")
	}
	if tag == "" || strings.ContainsAny(tag, "/\\?#") {
		return nil, fmt.Errorf("invalid recorder tag")
	}
	return &Client{base: u, tag: tag, username: username, password: password, http: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// Records returns one page; caller must follow NextCursor until empty and
// persist its own stable checkpoint. A partial pagination is never a complete
// interval and must not advance a high-water mark.
func (c *Client) Records(ctx context.Context, since, until time.Time, cursor string) (Page, error) {
	var out Page
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + "/api/plugins/" + c.tag + "/records"
	q := u.Query()
	q.Set("limit", "500")
	q.Set("since_ms", strconv.FormatInt(since.UnixMilli(), 10))
	q.Set("until_ms", strconv.FormatInt(until.UnixMilli(), 10))
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return out, err
	}
	if c.username != "" || c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return out, fmt.Errorf("OxiDNS request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("OxiDNS returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20+1))
	if err != nil {
		return out, err
	}
	if len(data) > 8<<20 {
		return out, fmt.Errorf("OxiDNS response too large")
	}
	if err = json.Unmarshal(data, &out); err != nil {
		return out, fmt.Errorf("invalid OxiDNS response: %w", err)
	}
	if !out.OK {
		return out, fmt.Errorf("OxiDNS returned unsuccessful response")
	}
	return out, nil
}
