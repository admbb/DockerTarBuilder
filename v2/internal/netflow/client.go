// Package netflow reads the existing NetFlow Plus HTTP API without modifying it.
package netflow

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

type Flow struct {
	ID       int64  `json:"id"`
	First    int64  `json:"first"`
	Last     int64  `json:"last"`
	LocalIP  string `json:"localIp"`
	RemoteIP string `json:"remoteIp"`
	Up       uint64 `json:"up"`
	Down     uint64 `json:"down"`
}
type FlowPage struct {
	Rows      []Flow `json:"rows"`
	FoldBelow uint64 `json:"foldBelow"`
}

type Overview struct {
	Range string `json:"range"`
	From  int64  `json:"from"`
	To    int64  `json:"to"`
	Up    uint64 `json:"up"`
	Down  uint64 `json:"down"`
	Conns uint64 `json:"conns"`
}

type Device struct {
	ID    int64    `json:"id"`
	Name  string   `json:"name"`
	IPs   []string `json:"ips"`
	Up    uint64   `json:"up"`
	Down  uint64   `json:"down"`
	Conns uint64   `json:"conns"`
}
type Client struct {
	base               *url.URL
	username, password string
	http               *http.Client
}

func NewClient(baseURL, username, password string) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("invalid NetFlow Plus URL")
	}
	return &Client{base: u, username: username, password: password, http: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// FlowSnapshot exposes cumulative, mutable connection counters. It does not
// imply that any returned bytes were transferred during the selected range.
// Offset pagination ordered by mutable counters is not a stable export cursor.
func (c *Client) FlowSnapshot(ctx context.Context, window string, offset int) (FlowPage, error) {
	var out FlowPage
	switch window {
	case "1h", "24h", "7d", "30d":
	default:
		return out, fmt.Errorf("unsupported range")
	}
	if offset < 0 {
		return out, fmt.Errorf("invalid offset")
	}
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + "/api/v1/flows"
	q := u.Query()
	q.Set("range", window)
	q.Set("sort", "time")
	q.Set("limit", "1000")
	q.Set("offset", strconv.Itoa(offset))
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
		return out, fmt.Errorf("NetFlow Plus request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("NetFlow Plus returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20+1))
	if err != nil {
		return out, err
	}
	if len(data) > 8<<20 {
		return out, fmt.Errorf("NetFlow Plus response too large")
	}
	if err = json.Unmarshal(data, &out); err != nil {
		return out, fmt.Errorf("invalid NetFlow Plus response: %w", err)
	}
	return out, nil
}

// Overview reads the source's existing aggregate. Its counters are never
// inferred from DNS, nor split into applications by this adapter.
func (c *Client) Overview(ctx context.Context, window string) (Overview, error) {
	var out Overview
	switch window {
	case "1h", "24h", "7d", "30d":
	default:
		return out, fmt.Errorf("unsupported range")
	}
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + "/api/v1/overview"
	q := u.Query()
	q.Set("range", window)
	q.Set("zone", "external")
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
		return out, fmt.Errorf("NetFlow Plus request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("NetFlow Plus returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20+1))
	if err != nil {
		return out, err
	}
	if len(data) > 8<<20 {
		return out, fmt.Errorf("NetFlow Plus response too large")
	}
	if err = json.Unmarshal(data, &out); err != nil {
		return out, fmt.Errorf("invalid NetFlow Plus overview: %w", err)
	}
	return out, nil
}

func (c *Client) Devices(ctx context.Context, window string) ([]Device, error) {
	switch window {
	case "1h", "24h", "7d", "30d":
	default:
		return nil, fmt.Errorf("unsupported range")
	}
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + "/api/v1/devices"
	q := u.Query()
	q.Set("range", window)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	if c.username != "" || c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("NetFlow Plus request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NetFlow Plus returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 8<<20 {
		return nil, fmt.Errorf("NetFlow Plus response too large")
	}
	var result struct {
		Devices []Device `json:"devices"`
	}
	if err = json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("invalid NetFlow Plus devices: %w", err)
	}
	return result.Devices, nil
}
