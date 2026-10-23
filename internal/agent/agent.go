// Package agent is the service: it samples, stores, watches for alerts,
// takes the inventory and reports, each on its own schedule.
package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tetrixdev/engram-agent/internal/alerts"
	"github.com/tetrixdev/engram-agent/internal/collect"
	"github.com/tetrixdev/engram-agent/internal/config"
	"github.com/tetrixdev/engram-agent/internal/identity"
	"github.com/tetrixdev/engram-agent/internal/inventory"
	"github.com/tetrixdev/engram-agent/internal/report"
	"github.com/tetrixdev/engram-agent/internal/state"
	"github.com/tetrixdev/engram-agent/internal/store"
)

// Meta keys the agent keeps in the history file.
const (
	metaEventsAgent   = "events.agent_id"    // the enrolment the event state below belongs to
	metaObserved      = "observed.sha256"    // the last server.observed summary sent
	metaFindings      = "findings.open"      // the findings opened and not resolved, JSON
	metaAlerts        = "alerts.tracks"      // the alert episodes, JSON
	metaUpdates       = "inventory.updates"  // the last update counts, JSON [count, security]
	metaStatePrefix   = "state.sha256."      // + section: the sha256 of the section last sent as state.observed
	metaFirewallAlert = "alerts.firewall"    // the raised firewall_uncommented alert, JSON; "" when not raised
	metaSnapshotBad   = "snapshot.bad_since" // when the snapshot was first seen not ok, RFC 3339; "" while ok

	// metaPortsBaseline was v0.1's enrolment baseline of listening ports
	// (the new_port finding, removed); it is cleared on start.
	metaPortsBaseline = "ports.baseline"
)

// The alert the agent raises itself when firewall rules lack a reason.
const (
	firewallRule   = "firewall_uncommented"
	firewallMetric = "firewall.uncommented_rules" // also the event ref, as for every alert
)

// snapshotFile is the root snapshot's file, under the configured root.
const snapshotFile = "var/lib/engram-agent-snapshot/state.json"

// Agent is the running service.
type Agent struct {
	Cfg      *config.Config
	Store    *store.Store
	Col      *collect.Collector
	Alerts   *alerts.Engine
	Outbox   *report.Outbox
	Reporter *report.Reporter
	Inv      inventory.Env
	Version  string
	Log      *log.Logger
	Interval time.Duration
	// SnapshotPath is the root snapshot's file; Interfaces lists the host's
	// network interfaces. Tests replace both.
	SnapshotPath string
	Interfaces   func() ([]state.Iface, error)

	snapStatus string // the snapshot's status at the last inventory, to log a change once
	invMu      sync.Mutex
	forceInv   atomic.Bool
	mu         sync.Mutex
	recent     []collect.Sample // the last few minutes, for the health summary
	agentID    string           // the enrolment events are being made for; "" while not enrolled
}

// New wires an agent from a configuration and an open store.
func New(cfg *config.Config, s *store.Store, version string, lg *log.Logger) (*Agent, error) {
	rules, err := alerts.Configure(cfg.Alerts)
	if err != nil {
		return nil, err
	}
	ob, err := report.OpenOutbox(s.DB())
	if err != nil {
		return nil, err
	}
	a := &Agent{Cfg: cfg, Store: s, Col: collect.New(cfg.Paths()), Alerts: alerts.New(rules), Outbox: ob, Version: version, Log: lg, Interval: 10 * time.Second}
	a.Inv = inventory.DefaultEnv()
	a.Inv.Root, a.Inv.Proc, a.Inv.Cgroup = cfg.Root, cfg.Proc, cfg.Cgroup
	a.SnapshotPath = filepath.Join(cfg.Root, snapshotFile)
	a.Interfaces = state.HostInterfaces
	if s.Meta(metaPortsBaseline) != "" {
		_ = s.SetMeta(metaPortsBaseline, "")
	}
	if err := a.Alerts.Load([]byte(s.Meta(metaAlerts))); err != nil {
		lg.Printf("alerts: the saved episodes could not be read (%v); starting fresh", err)
	}
	a.Reporter = &report.Reporter{
		Client: report.NewClient(version), StateDir: cfg.StateDir, Outbox: ob, Log: lg,
		Health:     func(at time.Time) *report.Health { return report.BuildHealth(a.Recent(), at, time.Minute) },
		Host:       func() *inventory.Host { h := a.Inv.HostFacts(); return &h },
		SetMeta:    func(k, v string) { _ = s.SetMeta(k, v) },
		OnIdentity: a.onIdentity,
	}
	if id, err := identity.Load(cfg.StateDir); err == nil && s.Meta(metaEventsAgent) == id.AgentID {
		a.agentID = id.AgentID
	}
	return a, nil
}

// Recent is a copy of the samples kept for the health summary.
func (a *Agent) Recent() []collect.Sample {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]collect.Sample(nil), a.recent...)
}

func (a *Agent) enrolled() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.agentID
}

// onIdentity runs when the reporter first sees an enrolment, or a new one:
// the event state of an earlier enrolment does not carry over, so Engram
// hears the current summary, the open findings and the raised alerts anew.
func (a *Agent) onIdentity(id *identity.Identity) {
	if a.Store.Meta(metaEventsAgent) == id.AgentID {
		a.mu.Lock()
		a.agentID = id.AgentID
		a.mu.Unlock()
		return
	}
	_ = a.Outbox.Clear()
	keys := []string{metaObserved, metaFindings}
	for _, n := range state.Names {
		keys = append(keys, metaStatePrefix+n)
	}
	for _, k := range keys {
		_ = a.Store.SetMeta(k, "")
	}
	_ = a.Store.SetMeta(metaEventsAgent, id.AgentID)
	a.mu.Lock()
	a.agentID = id.AgentID
	a.mu.Unlock()
	for _, ev := range a.Alerts.Raised() {
		a.add(ev.Type, ev.Ref, ev.At, ev.State)
	}
	if fa, ok := a.firewallAlertState(); ok {
		a.add("alert.raised", firewallMetric, fa.Since, fa.state())
	}
	a.forceInv.Store(true) // the loop takes the inventory at its next sample
}

func (a *Agent) add(typ, ref string, at time.Time, state any) {
	if a.enrolled() == "" {
		return
	}
	if err := a.Outbox.Add(typ, ref, at, state); err != nil {
		a.Log.Printf("events: %v", err)
	}
}

// Sample takes one sample, stores it and checks the alert rules.
func (a *Agent) Sample(now time.Time) collect.Sample {
	smp := a.Col.Collect()
	step := int64(a.Interval / time.Second)
	if step <= 0 {
		step = 1
	}
	t := smp.T.Unix()
	t -= t % step
	if err := a.Store.Write(t, smp.Values, smp.TopCPU, smp.TopMem); err != nil {
		a.Log.Printf("write sample: %v", err)
	}
	a.mu.Lock()
	a.recent = append(a.recent, smp)
	if len(a.recent) > 30 {
		a.recent = a.recent[len(a.recent)-30:]
	}
	a.mu.Unlock()
	evs := a.Alerts.Observe(smp.T, smp.Values)
	for _, ev := range evs {
		a.Log.Printf("alert: %s %s level %s value %v (threshold %v)", ev.Type, ev.Ref, ev.State.Level, ev.State.Value, ev.State.Threshold)
		a.add(ev.Type, ev.Ref, ev.At, ev.State)
	}
	if len(evs) > 0 {
		if b, err := a.Alerts.Save(); err == nil {
			_ = a.Store.SetMeta(metaAlerts, string(b))
		}
		a.Reporter.Kick() // alerts go at once, not with the next minute's report
	}
	return smp
}

// Inventory takes the inventory and turns what changed into events.
// withUpdates also asks apt for pending updates.
func (a *Agent) Inventory(ctx context.Context, withUpdates bool) {
	a.invMu.Lock()
	defer a.invMu.Unlock()
	full := a.Inv.Collect(ctx, a.Version, withUpdates)
	s := full.Summary
	if withUpdates && s.UpdatesCount != nil {
		b, _ := json.Marshal([]int{*s.UpdatesCount, *s.SecurityUpdatesCount})
		_ = a.Store.SetMeta(metaUpdates, string(b))
	} else {
		var c []int
		if json.Unmarshal([]byte(a.Store.Meta(metaUpdates)), &c) == nil && len(c) == 2 {
			s.UpdatesCount, s.SecurityUpdatesCount = &c[0], &c[1]
		}
	}
	for _, e := range full.Errors {
		a.Log.Printf("inventory: %s", e)
	}
	now := time.Now()
	snap := state.ReadSnapshot(a.SnapshotPath, now)
	if snap.Status != a.snapStatus {
		msg := "snapshot: " + a.SnapshotPath + " is " + snap.Status
		if snap.Err != nil {
			msg += ": " + *snap.Err
		}
		if snap.Status != state.SnapshotOK || a.snapStatus != "" {
			a.Log.Print(msg)
		}
		a.snapStatus = snap.Status
	}
	if a.enrolled() == "" {
		return
	}
	b, _ := json.Marshal(s)
	sum := sha256.Sum256(b)
	if h := hex.EncodeToString(sum[:]); h != a.Store.Meta(metaObserved) {
		a.add("server.observed", "host", now, s)
		_ = a.Store.SetMeta(metaObserved, h)
	}
	a.findings(s, snap, now)
	a.firewallAlert(snap, now)
	lo, hi := a.Inv.EphemeralRange()
	a.sendState(state.Collect(full, a.Inv.Root, lo, hi, a.Interfaces, snap, now), now)
}

// sendState queues every section whose sha256 differs from the one last
// sent, cut into parts; the five snapshot sections are only among them
// while the snapshot is ok, so the last ones sent stand meanwhile.
func (a *Agent) sendState(secs []state.Section, now time.Time) {
	for _, sec := range secs {
		sum := sec.SHA256()
		if sum == a.Store.Meta(metaStatePrefix+sec.Name) {
			continue
		}
		ok := true
		for _, ev := range sec.Events(now.Unix()) {
			if err := a.Outbox.AddKeyed("state.observed", ev.Ref, ev.Key, now, ev.State); err != nil {
				a.Log.Printf("events: %v", err)
				ok = false
			}
		}
		if ok {
			_ = a.Store.SetMeta(metaStatePrefix+sec.Name, sum)
		}
	}
}

// firewallRules are the snapshot's firewall rules that lack a reason, and
// whether they can be judged now: only from an ok snapshot whose firewall
// section was read without an error. Otherwise what was judged last stands.
func firewallRules(snap state.Snapshot) ([]state.FirewallRule, bool) {
	if snap.Status != state.SnapshotOK {
		return nil, false
	}
	sec, ok := snap.Find("firewall")
	if !ok || sec.Error != nil {
		return nil, false
	}
	return state.Uncommented(sec.Items), true
}

// firewallEpisode is the raised firewall_uncommented alert, kept in the
// history file so a restart neither forgets nor repeats it.
type firewallEpisode struct {
	Since time.Time `json:"since"`
	Value int       `json:"value"`
	Peak  int       `json:"peak"`
}

func (f firewallEpisode) state() alerts.State {
	return alerts.State{Rule: firewallRule, Metric: firewallMetric, Level: "warn", Threshold: 0,
		Value: float64(f.Value), Peak: float64(f.Peak), Since: f.Since.UTC().Format(time.RFC3339)}
}

func (a *Agent) firewallAlertState() (firewallEpisode, bool) {
	var f firewallEpisode
	raw := a.Store.Meta(metaFirewallAlert)
	if raw == "" || json.Unmarshal([]byte(raw), &f) != nil {
		return f, false
	}
	return f, true
}

// firewallAlert raises firewall_uncommented (level warn, at once) when at
// least one rule lacks a reason, and resolves it when none does.
func (a *Agent) firewallAlert(snap state.Snapshot, now time.Time) {
	rules, ok := firewallRules(snap)
	if !ok {
		return
	}
	n := len(rules)
	f, raised := a.firewallAlertState()
	switch {
	case n > 0 && !raised:
		f = firewallEpisode{Since: now.UTC(), Value: n, Peak: n}
		a.add("alert.raised", firewallMetric, now, f.state())
		a.Log.Printf("alert: alert.raised %s: %d firewall rules without a reason", firewallMetric, n)
		a.Reporter.Kick()
	case n > 0 && raised:
		if n == f.Value {
			return
		}
		f.Value = n
		f.Peak = max(f.Peak, n)
	case n == 0 && raised:
		st := f.state()
		st.Value = 0
		until := now.UTC().Format(time.RFC3339)
		d := now.Sub(f.Since).Seconds()
		st.Until, st.DurationS = &until, &d
		a.add("alert.resolved", firewallMetric, now, st)
		a.Log.Printf("alert: alert.resolved %s", firewallMetric)
		a.Reporter.Kick()
		_ = a.Store.SetMeta(metaFirewallAlert, "")
		return
	default:
		return
	}
	b, _ := json.Marshal(f)
	_ = a.Store.SetMeta(metaFirewallAlert, string(b))
}

// findings opens what is newly wrong and resolves what is no longer.
// An open finding the agent no longer makes (v0.1's new_port) is resolved
// here once, like any other that is no longer seen.
func (a *Agent) findings(s inventory.Summary, snap state.Snapshot, now time.Time) {
	cur := inventory.Findings(s)
	open := map[string]inventory.Finding{}
	_ = json.Unmarshal([]byte(a.Store.Meta(metaFindings)), &open)
	if rules, ok := firewallRules(snap); ok {
		for k, f := range state.FirewallFindings(rules) {
			cur[k] = f
		}
	} else {
		for k, f := range open { // not judged now: the open ones stand
			if strings.HasPrefix(k, state.FirewallFindingPrefix) {
				cur[k] = f
			}
		}
	}
	if snap.Status == state.SnapshotOK {
		_ = a.Store.SetMeta(metaSnapshotBad, "")
	} else {
		since, err := time.Parse(time.RFC3339, a.Store.Meta(metaSnapshotBad))
		if err != nil {
			since = now
			_ = a.Store.SetMeta(metaSnapshotBad, now.UTC().Format(time.RFC3339))
		}
		if now.Sub(since) > state.StaleAfter {
			cur["snapshot_not_running"] = state.SnapshotNotRunning(snap.Status, snap.Err)
		}
	}
	changed := false
	for _, k := range inventory.Keys(cur) {
		f := cur[k]
		old, was := open[k]
		f.Since = now.UTC().Format(time.RFC3339)
		if was {
			f.Since = old.Since
			if sameFinding(old, f) {
				continue
			}
		}
		a.add("finding.opened", k, now, f)
		open[k] = f
		changed = true
	}
	var gone []string
	for k := range open {
		if _, ok := cur[k]; !ok {
			gone = append(gone, k)
		}
	}
	sort.Strings(gone)
	for _, k := range gone {
		a.add("finding.resolved", k, now, open[k])
		delete(open, k)
		changed = true
	}
	if changed {
		b, _ := json.Marshal(open)
		_ = a.Store.SetMeta(metaFindings, string(b))
	}
}

func sameFinding(a, b inventory.Finding) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

// Run is the service loop: a sample every Interval, the store's maintenance
// once a minute, the inventory every 5 minutes (with apt's updates hourly
// and whenever dpkg's status file changes), and the reporter alongside.
func (a *Agent) Run(ctx context.Context, samples int) error {
	reporting := a.Cfg.Report == nil || *a.Cfg.Report
	var wg sync.WaitGroup
	defer wg.Wait()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if reporting {
		wg.Add(1)
		go func() { defer wg.Done(); a.Reporter.Run(ctx) }()
	}
	invDone := make(chan struct{}, 1)
	invDone <- struct{}{}
	var lastInv, lastUpdates, lastMaintain time.Time
	var dpkgStamp time.Time
	taken := 0
	for {
		n := time.Now()
		next := n.Truncate(a.Interval).Add(a.Interval)
		select {
		case <-ctx.Done():
			a.Log.Printf("stopping")
			return nil
		case <-time.After(next.Sub(n)):
		}
		smp := a.Sample(n)
		taken++
		last := samples > 0 && taken >= samples
		if smp.T.Unix()/60 != lastMaintain.Unix()/60 || last {
			if err := a.Store.Maintain(smp.T); err != nil {
				a.Log.Printf("maintain: %v", err)
			}
			if b, err := a.Alerts.Save(); err == nil {
				_ = a.Store.SetMeta(metaAlerts, string(b))
			}
			lastMaintain = smp.T
		}
		forced := a.forceInv.Load()
		if stamp := a.Inv.DpkgStamp(); forced || !stamp.Equal(dpkgStamp) || smp.T.Sub(lastInv) >= 5*time.Minute {
			withUpdates := forced || !stamp.Equal(dpkgStamp) || smp.T.Sub(lastUpdates) >= time.Hour
			select {
			case <-invDone: // one inventory at a time, off the sampling loop
				a.forceInv.Store(false)
				dpkgStamp, lastInv = stamp, smp.T
				if withUpdates {
					lastUpdates = smp.T
				}
				go func() {
					defer func() { invDone <- struct{}{} }()
					a.Inventory(ctx, withUpdates)
				}()
			default:
			}
		}
		if last {
			<-invDone
			return nil
		}
	}
}
