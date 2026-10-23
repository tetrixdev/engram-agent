package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/tetrixdev/engram-agent/internal/collect"
	"github.com/tetrixdev/engram-agent/internal/config"
	"github.com/tetrixdev/engram-agent/internal/identity"
	"github.com/tetrixdev/engram-agent/internal/inventory"
	"github.com/tetrixdev/engram-agent/internal/report"
	"github.com/tetrixdev/engram-agent/internal/state"
	"github.com/tetrixdev/engram-agent/internal/store"
)

type world struct {
	root, proc string
	failed     string // what systemctl --failed prints
}

func (w *world) file(t *testing.T, rel, content string) {
	t.Helper()
	p := filepath.Join(w.root, rel)
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func newAgent(t *testing.T) (*Agent, *world) {
	t.Helper()
	dir := t.TempDir()
	w := &world{root: filepath.Join(dir, "root")}
	w.proc = filepath.Join(w.root, "proc")
	w.file(t, "etc/ssh/sshd_config", "PasswordAuthentication no\nPermitRootLogin no\n")
	w.file(t, "proc/sys/kernel/osrelease", "6.8.0-1-generic\n")
	w.file(t, "proc/net/tcp", "  sl local rem st\n   0: 00000000:0016 00000000:0000 0A 0 0 0 0 0 1 1\n")
	cfg := &config.Config{StateDir: dir, DB: filepath.Join(dir, "history.db"), Root: w.root, Proc: w.proc, Sys: w.root, Cgroup: w.root}
	s, err := store.Open(cfg.DB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	a, err := New(cfg, s, "0.2.0", log.New(&bytes.Buffer{}, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	a.Inv = inventory.Env{Root: w.root, Proc: w.proc, Cgroup: w.root,
		Run: func(_ context.Context, name string, _ ...string) ([]byte, error) {
			if name == "systemctl" {
				return []byte(w.failed), nil
			}
			return nil, errors.New("no " + name)
		},
		Statfs: func(string) (collect.FsStat, error) { return collect.FsStat{}, nil },
	}
	a.Interfaces = func() ([]state.Iface, error) {
		return []state.Iface{{Name: "eth0", Addrs: []net.IP{net.ParseIP("203.0.113.10")}}}, nil
	}
	return a, w
}

// others are the events that are not state.observed.
func others(evs []report.Event) []report.Event {
	var out []report.Event
	for _, e := range evs {
		if e.Type != "state.observed" {
			out = append(out, e)
		}
	}
	return out
}

// stateRefs are the refs of the state.observed events.
func stateRefs(evs []report.Event) []string {
	var out []string
	for _, e := range evs {
		if e.Type == "state.observed" {
			out = append(out, e.Ref)
		}
	}
	return out
}

func events(t *testing.T, ob *report.Outbox) []report.Event {
	t.Helper()
	evs, err := ob.Pending(100)
	if err != nil {
		t.Fatal(err)
	}
	_ = ob.Ack(evs)
	return evs
}

func types(evs []report.Event) []string {
	var out []string
	for _, e := range evs {
		out = append(out, e.Type+" "+e.Ref)
	}
	return out
}

func TestEventsFollowTheInventory(t *testing.T) {
	a, w := newAgent(t)
	ctx := context.Background()
	// Not enrolled: nothing is queued.
	a.Inventory(ctx, false)
	if n := a.Outbox.Count(); n != 0 {
		t.Fatalf("queued %d before enrolment", n)
	}
	a.onIdentity(&identity.Identity{AgentID: "a-1", URL: "https://e.example.org"})
	if !a.forceInv.Load() {
		t.Fatal("a new enrolment did not ask for an inventory")
	}
	a.Inventory(ctx, false)
	first := events(t, a.Outbox)
	if got := types(others(first)); len(got) != 1 || got[0] != "server.observed host" {
		t.Fatalf("first inventory: %v", got)
	}
	// Without a snapshot only the agent's own sections and the snapshot's status go.
	if got := stateRefs(first); !reflect.DeepEqual(got, []string{"state:packages:1", "state:network", "state:ports", "state:snapshot"}) {
		t.Fatalf("first state: %v", got)
	}
	// Nothing changed: nothing sent.
	a.Inventory(ctx, false)
	if got := events(t, a.Outbox); len(got) != 0 {
		t.Fatalf("unchanged: %v", types(got))
	}
	// A unit fails and a port opens: summary changes, a finding opens, the
	// ports section is sent again; no new_port finding any more.
	w.failed = "nginx.service loaded failed failed nginx\n"
	w.file(t, "proc/net/tcp", "  sl local rem st\n   0: 00000000:0016 00000000:0000 0A 0 0 0 0 0 1 1\n   1: 00000000:0050 00000000:0000 0A 0 0 0 0 0 1 1\n")
	a.Inventory(ctx, false)
	all := events(t, a.Outbox)
	got := others(all)
	want := []string{"server.observed host", "finding.opened failed_unit:nginx.service"}
	if len(got) != 2 || types(got)[0] != want[0] || types(got)[1] != want[1] {
		t.Fatalf("after changes: %v", types(got))
	}
	if refs := stateRefs(all); !reflect.DeepEqual(refs, []string{"state:ports"}) {
		t.Fatalf("state after a new port: %v", refs)
	}
	var f inventory.Finding
	json.Unmarshal(got[1].State, &f)
	if f.Kind != "failed_unit" || f.Since == "" || *f.Subject != "nginx.service" {
		t.Fatalf("finding state %+v", f)
	}
	// The unit recovers: resolved, with the since it was opened with.
	w.failed = ""
	a.Inventory(ctx, false)
	got = others(events(t, a.Outbox))
	if len(got) != 2 || types(got)[1] != "finding.resolved failed_unit:nginx.service" {
		t.Fatalf("after recovery: %v", types(got))
	}
	var r inventory.Finding
	json.Unmarshal(got[1].State, &r)
	if r.Since != f.Since {
		t.Fatalf("resolved since %s, opened %s", r.Since, f.Since)
	}

	// A new enrolment starts over: the summary and the state are sent anew.
	a.Outbox.Add("alert.raised", "stale", time.Now(), map[string]string{})
	a.onIdentity(&identity.Identity{AgentID: "a-2", URL: "https://e.example.org"})
	a.Inventory(ctx, false)
	all = events(t, a.Outbox)
	got = others(all)
	if len(got) != 1 || types(got)[0] != "server.observed host" {
		t.Fatalf("after re-enrolment: %v", types(got))
	}
	// and every state section anew.
	if refs := stateRefs(all); len(refs) != 4 {
		t.Fatalf("state after re-enrolment: %v", refs)
	}
}

func TestAlertsAreQueuedAndKick(t *testing.T) {
	a, _ := newAgent(t)
	a.onIdentity(&identity.Identity{AgentID: "a-1", URL: "https://e.example.org"})
	events(t, a.Outbox)
	// A sample over the disk threshold raises at once (disk has no duration).
	a.Col = collect.New(collect.Paths{Proc: t.TempDir(), Sys: t.TempDir(), Cgroup: t.TempDir()})
	vals := map[string]float64{"disk_pct:/": 96}
	evs := a.Alerts.Observe(time.Now(), vals)
	for _, ev := range evs {
		a.add(ev.Type, ev.Ref, ev.At, ev.State)
	}
	got := events(t, a.Outbox)
	if len(got) != 1 || got[0].Type != "alert.raised" || got[0].Ref != "disk_pct:/" {
		t.Fatalf("%v", types(got))
	}
	var st map[string]any
	json.Unmarshal(got[0].State, &st)
	for _, k := range []string{"rule", "metric", "level", "threshold", "value", "peak", "since"} {
		if _, ok := st[k]; !ok {
			t.Errorf("alert state lacks %s", k)
		}
	}
	if len(st) != 7 {
		t.Errorf("alert state keys %v", st)
	}
	// A new enrolment re-sends what is raised.
	a.onIdentity(&identity.Identity{AgentID: "a-9", URL: "https://e.example.org"})
	if got := events(t, a.Outbox); len(got) != 1 || got[0].Ref != "disk_pct:/" {
		t.Fatalf("raised alerts after re-enrolment: %v", types(got))
	}
}
