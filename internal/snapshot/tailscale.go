package snapshot

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Tailnet is this machine as Tailscale sees itself.
type Tailnet struct {
	Hostname     string   `json:"hostname"`
	DNSName      string   `json:"dns_name"` // without the trailing dot
	Online       bool     `json:"online"`
	Addresses    []string `json:"addresses"`
	Tags         []string `json:"tags"`
	BackendState string   `json:"backend_state"` // Running, Stopped, NeedsLogin, ...; NoState when tailscaled cannot be reached
}

type tsStatus struct {
	BackendState string
	Self         *struct {
		HostName     string
		DNSName      string
		Online       bool
		TailscaleIPs []string
		Tags         []string
	}
}

// ParseTailscale reads `tailscale status --json`, Self only.
func ParseTailscale(out []byte) (Tailnet, error) {
	var st tsStatus
	if err := json.Unmarshal(out, &st); err != nil {
		return Tailnet{}, fmt.Errorf("tailscale status --json: %w", err)
	}
	t := Tailnet{BackendState: st.BackendState, Addresses: []string{}, Tags: []string{}}
	if st.Self != nil {
		t.Hostname = st.Self.HostName
		t.DNSName = strings.TrimSuffix(st.Self.DNSName, ".")
		t.Online = st.Self.Online && st.BackendState == "Running"
		if st.Self.TailscaleIPs != nil {
			t.Addresses = append(t.Addresses, st.Self.TailscaleIPs...)
		}
		if st.Self.Tags != nil {
			t.Tags = append(t.Tags, st.Self.Tags...)
		}
	}
	sort.Strings(t.Addresses)
	sort.Strings(t.Tags)
	return t, nil
}

// Tailscale asks the tailscale CLI (which talks to tailscaled over its
// unix socket) for this machine's own state.
func (e Env) Tailscale(ctx context.Context) Section {
	p := e.lookPath("tailscale", "usr/bin", "usr/sbin", "usr/local/bin")
	if p == "" {
		return Section{Items: []Tailnet{}, Meta: map[string]any{"installed": false}}
	}
	meta := map[string]any{"installed": true}
	out, runErr := e.Run(ctx, p, "status", "--json")
	t, err := ParseTailscale(out)
	if err == nil {
		return Section{Items: []Tailnet{t}, Meta: meta}
	}
	if runErr != nil {
		msg := runErr.Error()
		// tailscaled not running: installed but not up.
		if strings.Contains(msg, "tailscaled") || strings.Contains(msg, "connect") {
			return Section{Items: []Tailnet{{Addresses: []string{}, Tags: []string{}, BackendState: "NoState"}}, Meta: meta}
		}
		return Section{Items: []Tailnet{}, Meta: meta, Error: errp(fmt.Errorf("tailscale status --json: %s", msg))}
	}
	return Section{Items: []Tailnet{}, Meta: meta, Error: errp(err)}
}
