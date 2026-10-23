package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tetrixdev/engram-agent/internal/identity"
	"github.com/tetrixdev/engram-agent/internal/inventory"
	"github.com/tetrixdev/engram-agent/internal/report"
	"github.com/tetrixdev/engram-agent/internal/state"
)

// writeSnapshot writes a snapshot file with these firewall rules.
func writeSnapshot(t *testing.T, a *Agent, at time.Time, rules string) {
	t.Helper()
	doc := fmt.Sprintf(`{"version":1,"collected_at":%q,"agent_version":"0.2.0","sections":{
	 "firewall":{"items":[%s],"meta":{"policies":{"v4":{"INPUT":"DROP"}},"backend":"nf_tables"},"error":null},
	 "containers":{"items":[{"name":"proxy-nginx","image":"nginx:1","image_id":"sha256:a","state":"running","compose_project":null,"compose_service":null,"published":["0.0.0.0:443->443/tcp"]}],"meta":{"docker":true},"error":null},
	 "users":{"items":[{"login":"root","uid":0,"shell":"/bin/bash","groups":["root"],"sudo":"password"}],"meta":{},"error":null},
	 "ssh_keys":{"items":[],"meta":{},"error":null},
	 "tailscale":{"items":[],"meta":{"installed":false},"error":null}}}`, at.UTC().Format(time.RFC3339), rules)
	os.MkdirAll(filepath.Dir(a.SnapshotPath), 0o755)
	if err := os.WriteFile(a.SnapshotPath, []byte(doc), 0o640); err != nil {
		t.Fatal(err)
	}
}

const (
	ruleOK    = `{"family":"v4","chain":"INPUT","rule":"-p tcp -m tcp --dport 443 -j ACCEPT","comment":"web: proxy serves the sites; 80 for ACME","target":"ACCEPT"}`
	ruleBare  = `{"family":"v4","chain":"INPUT","rule":"-p tcp -m tcp --dport 22 -j ACCEPT","comment":null,"target":"ACCEPT"}`
	ruleBare6 = `{"family":"v6","chain":"INPUT","rule":"-p tcp -m tcp --dport 22 -j ACCEPT","comment":"todo","target":"ACCEPT"}`
	ruleJump  = `{"family":"v4","chain":"INPUT","rule":"-j ts-input","comment":null,"target":"ts-input"}`
)

func byType(evs []report.Event, typ string) []report.Event {
	var out []report.Event
	for _, e := range evs {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

func keysOf(m map[string]any) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}

func TestSnapshotStateFirewallFindingsAndAlert(t *testing.T) {
	a, _ := newAgent(t)
	ctx := context.Background()
	now := time.Now()
	writeSnapshot(t, a, now, strings.Join([]string{ruleJump, ruleOK, ruleBare, ruleBare6}, ","))
	a.onIdentity(&identity.Identity{AgentID: "a-1", URL: "https://e.example.org"})
	a.Inventory(ctx, false)
	evs := events(t, a.Outbox)

	// Every section, the snapshot's five included.
	refs := stateRefs(evs)
	want := []string{"state:packages:1", "state:network", "state:ports", "state:firewall", "state:containers", "state:users", "state:ssh_keys", "state:tailscale", "state:snapshot"}
	if !reflect.DeepEqual(refs, want) {
		t.Fatalf("state refs %v", refs)
	}
	for _, ev := range byType(evs, "state.observed") {
		var st map[string]any
		json.Unmarshal(ev.State, &st)
		if got := keysOf(st); !reflect.DeepEqual(got, []string{"collected_at", "error", "items", "meta", "part", "parts", "section", "sha256"}) {
			t.Fatalf("%s state keys %v", ev.Ref, got)
		}
		if !strings.HasPrefix(ev.Key, "state:"+st["section"].(string)+":1:"+st["sha256"].(string)[:16]+":") {
			t.Errorf("%s key %s", ev.Ref, ev.Key)
		}
		if ev.Ref == "state:firewall" && st["collected_at"] != now.UTC().Format(time.RFC3339) {
			t.Errorf("firewall collected_at %v: the snapshot's own", st["collected_at"])
		}
		if ev.Ref == "state:snapshot" && st["meta"].(map[string]any)["status"] != "ok" {
			t.Errorf("snapshot meta %v", st["meta"])
		}
	}

	// Two rules lack a reason: two findings, one alert raised at once.
	var opened []string
	for _, ev := range byType(evs, "finding.opened") {
		opened = append(opened, ev.Ref)
		var f inventory.Finding
		json.Unmarshal(ev.State, &f)
		if f.Kind != "firewall_rule_uncommented" || f.Severity != "high" {
			t.Errorf("finding %+v", f)
		}
	}
	sort.Strings(opened)
	if len(opened) != 2 || !strings.HasPrefix(opened[0], "firewall_uncommented:v4:INPUT:") || !strings.HasPrefix(opened[1], "firewall_uncommented:v6:INPUT:") {
		t.Fatalf("findings %v", opened)
	}
	raised := byType(evs, "alert.raised")
	if len(raised) != 1 || raised[0].Ref != "firewall.uncommented_rules" {
		t.Fatalf("alerts %v", types(evs))
	}
	var st map[string]any
	json.Unmarshal(raised[0].State, &st)
	if got := keysOf(st); !reflect.DeepEqual(got, []string{"level", "metric", "peak", "rule", "since", "threshold", "value"}) {
		t.Fatalf("alert keys %v", got)
	}
	if st["rule"] != "firewall_uncommented" || st["metric"] != "firewall.uncommented_rules" || st["level"] != "warn" || st["value"] != 2.0 || st["threshold"] != 0.0 {
		t.Fatalf("alert %v", st)
	}

	// Nothing changed: nothing sent, not even after a restart (the alert is kept).
	a.Inventory(ctx, false)
	if got := events(t, a.Outbox); len(got) != 0 {
		t.Fatalf("unchanged: %v", types(got))
	}
	b, err := New(a.Cfg, a.Store, "0.2.0", log.New(&bytes.Buffer{}, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	b.Inv, b.Interfaces, b.SnapshotPath = a.Inv, a.Interfaces, a.SnapshotPath
	b.onIdentity(&identity.Identity{AgentID: "a-1", URL: "https://e.example.org"})
	b.Inventory(ctx, false)
	if got := events(t, b.Outbox); len(got) != 0 {
		t.Fatalf("after a restart: %v", types(got))
	}

	// The snapshot goes stale: only its status is sent, the firewall findings
	// and the alert stand.
	writeSnapshot(t, a, now.Add(-time.Hour), ruleOK)
	b.Inventory(ctx, false)
	got := events(t, b.Outbox)
	if refs := stateRefs(got); !reflect.DeepEqual(refs, []string{"state:snapshot"}) || len(others(got)) != 0 {
		t.Fatalf("stale: %v", types(got))
	}
	var ss map[string]any
	json.Unmarshal(got[0].State, &ss)
	if ss["meta"].(map[string]any)["status"] != "stale" {
		t.Fatalf("stale meta %v", ss["meta"])
	}
	// Not ok for over 30 minutes: snapshot_not_running.
	b.Store.SetMeta(metaSnapshotBad, time.Now().Add(-31*time.Minute).UTC().Format(time.RFC3339))
	b.Inventory(ctx, false)
	got = others(events(t, b.Outbox))
	if len(got) != 1 || got[0].Type != "finding.opened" || got[0].Ref != "snapshot_not_running" {
		t.Fatalf("not running: %v", types(got))
	}
	var nr inventory.Finding
	json.Unmarshal(got[0].State, &nr)
	if nr.Category != "maintenance" || nr.Severity != "medium" || !strings.Contains(*nr.Detail, "systemctl status engram-agent-snapshot.timer") {
		t.Fatalf("not running finding %+v", nr)
	}

	// Fresh again, every rule with a reason: the findings resolve, the alert
	// resolves with until and duration_s, and the sections that changed go.
	writeSnapshot(t, a, time.Now(), strings.Join([]string{ruleJump, ruleOK}, ","))
	b.Inventory(ctx, false)
	got = events(t, b.Outbox)
	if refs := stateRefs(got); !reflect.DeepEqual(refs, []string{"state:firewall", "state:snapshot"}) {
		t.Fatalf("fresh refs %v", refs)
	}
	if res := byType(got, "finding.resolved"); len(res) != 3 {
		t.Fatalf("resolved %v", types(got))
	}
	res := byType(got, "alert.resolved")
	if len(res) != 1 {
		t.Fatalf("alert not resolved: %v", types(got))
	}
	json.Unmarshal(res[0].State, &st)
	if got := keysOf(st); !reflect.DeepEqual(got, []string{"duration_s", "level", "metric", "peak", "rule", "since", "threshold", "until", "value"}) {
		t.Fatalf("resolved keys %v", got)
	}
	if st["peak"] != 2.0 || st["value"] != 0.0 {
		t.Fatalf("resolved %v", st)
	}
	if b.Store.Meta(metaFirewallAlert) != "" {
		t.Fatal("the resolved alert is still kept")
	}
}

func TestUpgradeResolvesNewPort(t *testing.T) {
	a, _ := newAgent(t)
	a.Store.SetMeta(metaEventsAgent, "a-1")
	a.Store.SetMeta(metaPortsBaseline, `["tcp/22"]`)
	open := map[string]inventory.Finding{"new_port:tcp/8080": {Kind: "new_port", Category: "security", Severity: "medium", Title: "New listening port tcp/8080", Since: "2026-10-20T10:00:00Z"}}
	b, _ := json.Marshal(open)
	a.Store.SetMeta(metaFindings, string(b))
	// What starts after the upgrade.
	a2, err := New(a.Cfg, a.Store, "0.2.0", log.New(&bytes.Buffer{}, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	a2.Inv, a2.Interfaces, a2.SnapshotPath = a.Inv, a.Interfaces, a.SnapshotPath
	if a2.Store.Meta(metaPortsBaseline) != "" {
		t.Fatal("the port baseline is still kept")
	}
	a2.onIdentity(&identity.Identity{AgentID: "a-1", URL: "https://e.example.org"})
	a2.Inventory(context.Background(), false)
	got := byType(events(t, a2.Outbox), "finding.resolved")
	if len(got) != 1 || got[0].Ref != "new_port:tcp/8080" {
		t.Fatalf("resolved %v", types(got))
	}
	a2.Inventory(context.Background(), false)
	if got := byType(events(t, a2.Outbox), "finding.resolved"); len(got) != 0 {
		t.Fatalf("resolved twice: %v", types(got))
	}
}

func TestLargePackageListIsChunked(t *testing.T) {
	a, w := newAgent(t)
	var b strings.Builder
	for i := 0; i < 1500; i++ {
		fmt.Fprintf(&b, "Package: lib-package-number-%05d\nStatus: install ok installed\nArchitecture: amd64\nSource: src-%05d (1.2.3-4)\nVersion: 1.2.3-4ubuntu0.24.04.1\n\n", i, i)
	}
	w.file(t, "var/lib/dpkg/status", b.String())
	w.file(t, "var/lib/apt/extended_states", "Package: lib-package-number-00001\nArchitecture: amd64\nAuto-Installed: 1\n")
	a.onIdentity(&identity.Identity{AgentID: "a-1", URL: "https://e.example.org"})
	a.Inventory(context.Background(), false)
	var parts []report.Event
	for _, ev := range byType(events(t, a.Outbox), "state.observed") {
		if strings.HasPrefix(ev.Ref, "state:packages:") {
			parts = append(parts, ev)
		}
	}
	if len(parts) != 3 {
		t.Fatalf("%d parts", len(parts))
	}
	var sum string
	n := 0
	for i, p := range parts {
		var ps state.PartState
		json.Unmarshal(p.State, &ps)
		if len(p.State) >= state.MaxPartBytes || ps.Part != i+1 || ps.Parts != 3 || (sum != "" && ps.SHA256 != sum) {
			t.Fatalf("part %d: %d bytes, %+v", i+1, len(p.State), ps.Part)
		}
		sum = ps.SHA256
		n += len(ps.Items)
		if i == 0 && string(ps.Items[1]) != `["lib-package-number-00001","1.2.3-4ubuntu0.24.04.1","src-00001 (1.2.3-4)","amd64",false]` {
			t.Fatalf("item %s", ps.Items[1])
		}
	}
	if n != 1500 {
		t.Fatalf("%d packages across the parts", n)
	}
}
