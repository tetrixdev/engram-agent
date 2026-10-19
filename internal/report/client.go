package report

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tetrixdev/engram/agent/internal/collect"
	"github.com/tetrixdev/engram/agent/internal/identity"
	"github.com/tetrixdev/engram/agent/internal/inventory"
)

// MaxBody is the most a report may carry (the protocol's 256 KB).
const MaxBody = 256 << 10

// MaxEvents is the most events one report carries.
const MaxEvents = 20

// Client talks to one Engram.
type Client struct {
	HTTP    *http.Client
	Version string
	Now     func() time.Time
}

// NewClient is a client with a 20-second timeout.
func NewClient(version string) *Client {
	return &Client{HTTP: &http.Client{Timeout: 20 * time.Second}, Version: version, Now: time.Now}
}

// EnrolRequest is POST /agent/v1/enrol.
type EnrolRequest struct {
	Code         string `json:"code"`
	PublicKey    string `json:"public_key"`
	Hostname     string `json:"hostname"`
	AgentVersion string `json:"agent_version"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
}

// EnrolResponse is its 200 answer.
type EnrolResponse struct {
	AgentID      string `json:"agent_id"`
	Fingerprint  string `json:"fingerprint"`
	ReportEveryS int    `json:"report_every_s"`
}

// APIError is a refusal from Engram: the HTTP status and the body's code and error.
type APIError struct {
	Status  int
	Code    string `json:"code"`
	Message string `json:"error"`
	Date    time.Time
	Retry   time.Duration
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("Engram answered %d", e.Status)
	if e.Code != "" {
		msg += " " + e.Code
	}
	if e.Message != "" {
		msg += ": " + e.Message
	}
	return msg
}

func (c *Client) post(ctx context.Context, url string, body []byte, hdr map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "engram-agent/"+c.Version)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusOK {
		return b, nil
	}
	ae := &APIError{Status: resp.StatusCode}
	_ = json.Unmarshal(b, ae)
	if ae.Message == "" && ae.Code == "" {
		ae.Message = strings.TrimSpace(string(b))
		if len(ae.Message) > 200 {
			ae.Message = ae.Message[:200]
		}
	}
	if d, err := http.ParseTime(resp.Header.Get("Date")); err == nil {
		ae.Date = d
	}
	if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil {
		ae.Retry = time.Duration(s) * time.Second
	}
	return nil, ae
}

// Enrol presents a one-time code and this agent's public key.
func (c *Client) Enrol(ctx context.Context, origin string, req EnrolRequest) (*EnrolResponse, error) {
	body, _ := json.Marshal(req)
	b, err := c.post(ctx, origin+"/agent/v1/enrol", body, nil)
	if err != nil {
		var ae *APIError
		if errors.As(err, &ae) {
			switch ae.Code {
			case "bad_code", "invalid":
				return nil, fmt.Errorf("the code was not accepted (%s): check it, or make a new one in the Servers app", ae.Message)
			case "expired":
				return nil, errors.New("the code has expired (codes last 15 minutes): make a new one in the Servers app")
			case "used":
				return nil, errors.New("the code was already used: make a new one in the Servers app")
			}
		}
		return nil, err
	}
	var r EnrolResponse
	if err := json.Unmarshal(b, &r); err != nil || r.AgentID == "" {
		return nil, fmt.Errorf("Engram's answer to the enrolment is not what was expected: %s", truncate(string(b), 200))
	}
	return &r, nil
}

// Report is the body of POST /agent/v1/report.
type Report struct {
	AgentVersion string          `json:"agent_version"`
	Host         *inventory.Host `json:"host,omitempty"`
	Health       *Health         `json:"health,omitempty"`
	Events       []Event         `json:"events"`
}

// Answer is the 200 answer to a report.
type Answer struct {
	OK           bool `json:"ok"`
	Accepted     int  `json:"accepted"`
	ReportEveryS int  `json:"report_every_s"`
}

// Send signs and posts one report body.
func (c *Client) Send(ctx context.Context, id *identity.Identity, key ed25519.PrivateKey, body []byte) (*Answer, error) {
	now := c.Now().Unix()
	hdr := map[string]string{
		"X-Engram-Agent":     id.AgentID,
		"X-Engram-Time":      strconv.FormatInt(now, 10),
		"X-Engram-Signature": identity.Sign(key, id.AgentID, now, body),
	}
	b, err := c.post(ctx, id.URL+"/agent/v1/report", body, hdr)
	if err != nil {
		return nil, err
	}
	var a Answer
	_ = json.Unmarshal(b, &a)
	return &a, nil
}

// PublicKeyB64 is the raw 32-byte public key, base64 standard.
func PublicKeyB64(key ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// Health is the report's summary of the last minute.
type Health struct {
	At        string             `json:"at"`
	WindowS   int                `json:"window_s"`
	CPUPct    *AvgMax            `json:"cpu_pct,omitempty"`
	Load1     *float64           `json:"load1,omitempty"`
	MemoryPct *AvgMax            `json:"memory_pct,omitempty"`
	SwapPct   *float64           `json:"swap_pct,omitempty"`
	Disk      []Disk             `json:"disk"`
	Pressure  map[string]float64 `json:"pressure,omitempty"`
	Net       *Net               `json:"net,omitempty"`
}

// AvgMax is the average and maximum over the window.
type AvgMax struct {
	Avg float64 `json:"avg"`
	Max float64 `json:"max"`
}

// Disk is one mount's latest use.
type Disk struct {
	Mount     string   `json:"mount"`
	UsedPct   float64  `json:"used_pct"`
	InodesPct *float64 `json:"inodes_pct,omitempty"`
}

// Net is the average network rate over the window.
type Net struct {
	RxBps float64 `json:"rx_bps"`
	TxBps float64 `json:"tx_bps"`
}

func r2(f float64) float64 { return float64(int64(f*100+0.5)) / 100 }

// BuildHealth summarises the samples of the last window: averages and
// maxima for cpu and memory, the latest value for the rest.
func BuildHealth(samples []collect.Sample, at time.Time, window time.Duration) *Health {
	h := &Health{At: at.UTC().Format(time.RFC3339), WindowS: int(window / time.Second), Disk: []Disk{}}
	var in []collect.Sample
	for _, s := range samples {
		if !s.T.Before(at.Add(-window)) && !s.T.After(at) {
			in = append(in, s)
		}
	}
	if len(in) == 0 {
		return h
	}
	am := func(name string) *AvgMax {
		var sum, max float64
		n := 0
		for _, s := range in {
			if v, ok := s.Values[name]; ok {
				if n == 0 || v > max {
					max = v
				}
				sum += v
				n++
			}
		}
		if n == 0 {
			return nil
		}
		return &AvgMax{Avg: r2(sum / float64(n)), Max: r2(max)}
	}
	avg := func(name string) *float64 {
		if a := am(name); a != nil {
			return &a.Avg
		}
		return nil
	}
	last := in[len(in)-1].Values
	lastOf := func(name string) *float64 {
		if v, ok := last[name]; ok {
			return &v
		}
		return nil
	}
	h.CPUPct, h.MemoryPct = am("cpu_pct"), am("memory_pct")
	h.Load1, h.SwapPct = lastOf("load1"), lastOf("swap_pct")
	h.Pressure = map[string]float64{}
	for _, k := range []string{"cpu_some", "memory_some", "memory_full", "io_some", "io_full"} {
		if v, ok := last["pressure."+k]; ok {
			h.Pressure[k] = v
		}
	}
	if len(h.Pressure) == 0 {
		h.Pressure = nil
	}
	var mounts []string
	for k := range last {
		if strings.HasPrefix(k, "disk_pct:") {
			mounts = append(mounts, strings.TrimPrefix(k, "disk_pct:"))
		}
	}
	sort.Strings(mounts)
	for _, m := range mounts {
		d := Disk{Mount: m, UsedPct: last["disk_pct:"+m]}
		if v, ok := last["inodes_pct:"+m]; ok {
			d.InodesPct = &v
		}
		h.Disk = append(h.Disk, d)
	}
	if rx, tx := avg("net_rx_bps"), avg("net_tx_bps"); rx != nil && tx != nil {
		h.Net = &Net{RxBps: *rx, TxBps: *tx}
	}
	return h
}
