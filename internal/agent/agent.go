// Package agent is the service: it samples, stores, watches for alerts,
// takes the inventory and reports, each on its own schedule.
package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tetrixdev/engram-agent/internal/alerts"
	"github.com/tetrixdev/engram-agent/internal/collect"
	"github.com/tetrixdev/engram-agent/internal/config"
	"github.com/tetrixdev/engram-agent/internal/identity"
	"github.com/tetrixdev/engram-agent/internal/inventory"
	"github.com/tetrixdev/engram-agent/internal/report"
	"github.com/tetrixdev/engram-agent/internal/store"
)

// Meta keys the agent keeps in the history file.
const (
	metaEventsAgent   = "events.agent_id"   // the enrolment the event state below belongs to
	metaObserved      = "observed.sha256"   // the last server.observed summary sent
	metaFindings      = "findings.open"     // the findings opened and not resolved, JSON
	metaPortsBaseline = "ports.baseline"    // listening ports at the first inventory after enrolment, JSON
	metaAlerts        = "alerts.tracks"     // the alert episodes, JSON
	metaUpdates       = "inventory.updates" // the last update counts, JSON [count, security]
)

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

	invMu    sync.Mutex
	forceInv atomic.Bool
	mu       sync.Mutex
	recent   []collect.Sample // the last few minutes, for the health summary
	agentID  string           // the enrolment events are being made for; "" while not enrolled
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
	for _, k := range []string{metaObserved, metaFindings, metaPortsBaseline} {
		_ = a.Store.SetMeta(k, "")
	}
	_ = a.Store.SetMeta(metaEventsAgent, id.AgentID)
	a.mu.Lock()
	a.agentID = id.AgentID
	a.mu.Unlock()
	for _, ev := range a.Alerts.Raised() {
		a.add(ev.Type, ev.Ref, ev.At, ev.State)
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
	if a.enrolled() == "" {
		return
	}
	now := time.Now()
	b, _ := json.Marshal(s)
	sum := sha256.Sum256(b)
	if h := hex.EncodeToString(sum[:]); h != a.Store.Meta(metaObserved) {
		a.add("server.observed", "host", now, s)
		_ = a.Store.SetMeta(metaObserved, h)
	}
	a.findings(s, now)
}

// findings opens what is newly wrong and resolves what is no longer.
func (a *Agent) findings(s inventory.Summary, now time.Time) {
	var baseline map[string]bool
	if raw := a.Store.Meta(metaPortsBaseline); raw == "" {
		baseline = map[string]bool{}
		for _, p := range s.Listening {
			baseline[p] = true
		}
		bb, _ := json.Marshal(s.Listening)
		_ = a.Store.SetMeta(metaPortsBaseline, string(bb))
	} else {
		var list []string
		_ = json.Unmarshal([]byte(raw), &list)
		baseline = map[string]bool{}
		for _, p := range list {
			baseline[p] = true
		}
	}
	lo, hi := a.Inv.EphemeralRange()
	cur := inventory.Findings(s, baseline, lo, hi)
	open := map[string]inventory.Finding{}
	_ = json.Unmarshal([]byte(a.Store.Meta(metaFindings)), &open)
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
