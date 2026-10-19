// Package alerts watches the samples for saturation: a value over a rule's
// threshold for long enough raises an alert, and one back under the
// threshold (with hysteresis) for long enough resolves it.
package alerts

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

// Rule is one saturation rule. Metric is a metric name, or a prefix ending in
// '*' for one alert per matching metric (disk_pct:* is one per mount).
type Rule struct {
	Name     string        `json:"-"`
	Metric   string        `json:"-"`
	Warn     float64       `json:"warn"`
	Crit     float64       `json:"crit"` // 0: no crit level
	For      time.Duration `json:"-"`
	ClearFor time.Duration `json:"-"`
	// Clear is the fraction of the threshold the value must drop below to
	// count as recovered: 0.95 means under 85.5 for a threshold of 90.
	Clear float64 `json:"clear_fraction"`
	Off   bool    `json:"off"`
}

// Defaults are the built-in rules.
func Defaults() []Rule {
	m := time.Minute
	return []Rule{
		{Name: "memory_pct", Metric: "memory_pct", Warn: 90, Crit: 97, For: 5 * m},
		{Name: "disk_pct", Metric: "disk_pct:*", Warn: 85, Crit: 95},
		{Name: "inodes_pct", Metric: "inodes_pct:*", Warn: 85, Crit: 95},
		{Name: "cpu_pct", Metric: "cpu_pct", Warn: 90, For: 10 * m},
		{Name: "pressure.memory_full", Metric: "pressure.memory_full", Warn: 5, For: 2 * m},
		{Name: "pressure.io_full", Metric: "pressure.io_full", Warn: 20, For: 5 * m},
		{Name: "swap_pct", Metric: "swap_pct", Warn: 50, For: 10 * m},
	}
}

// Override is how the configuration file changes a rule, by rule name.
type Override struct {
	Warn      *float64 `json:"warn"`
	Crit      *float64 `json:"crit"`
	ForS      *int     `json:"for_s"`
	ClearForS *int     `json:"clear_for_s"`
	Clear     *float64 `json:"clear_fraction"`
	Off       *bool    `json:"off"`
}

// Configure applies overrides to the defaults; an unknown rule name is an error.
func Configure(over map[string]json.RawMessage) ([]Rule, error) {
	rules := Defaults()
	for name, raw := range over {
		i := -1
		for j := range rules {
			if rules[j].Name == name {
				i = j
			}
		}
		if i < 0 {
			var names []string
			for _, r := range rules {
				names = append(names, r.Name)
			}
			return nil, fmt.Errorf("alerts: unknown rule %q (the rules are %s)", name, strings.Join(names, ", "))
		}
		var o Override
		if err := json.Unmarshal(raw, &o); err != nil {
			return nil, fmt.Errorf("alerts.%s: %w", name, err)
		}
		r := &rules[i]
		if o.Warn != nil {
			r.Warn = *o.Warn
		}
		if o.Crit != nil {
			r.Crit = *o.Crit
		}
		if o.ForS != nil {
			r.For = time.Duration(*o.ForS) * time.Second
		}
		if o.ClearForS != nil {
			r.ClearFor = time.Duration(*o.ClearForS) * time.Second
		}
		if o.Clear != nil {
			r.Clear = *o.Clear
		}
		if o.Off != nil {
			r.Off = *o.Off
		}
	}
	return rules, nil
}

// Event is an alert.raised or alert.resolved, with the state the Servers app declares.
type Event struct {
	Type  string
	Ref   string
	At    time.Time
	State State
}

// State is the event state: rule, metric, level, threshold, value, peak, since, and when resolved until and duration_s.
type State struct {
	Rule      string   `json:"rule"`
	Metric    string   `json:"metric"`
	Level     string   `json:"level"`
	Threshold float64  `json:"threshold"`
	Value     float64  `json:"value"`
	Peak      float64  `json:"peak"`
	Since     string   `json:"since"`
	Until     *string  `json:"until,omitempty"`
	DurationS *float64 `json:"duration_s,omitempty"`
}

// track is one metric's episode, raised or pending.
type track struct {
	Rule       string    `json:"rule"`
	Metric     string    `json:"metric"`
	WarnSince  time.Time `json:"warn_since"`
	CritSince  time.Time `json:"crit_since"`
	BelowSince time.Time `json:"below_since"`
	Peak       float64   `json:"peak"`
	Level      string    `json:"level"` // "" while pending, else the level last raised
	Last       float64   `json:"last"`
}

// Engine evaluates samples against rules.
type Engine struct {
	Rules  []Rule
	mu     sync.Mutex // the sampling loop observes; the reporter reads Raised
	tracks map[string]*track
}

// New returns an engine with these rules and no episodes.
func New(rules []Rule) *Engine {
	for i := range rules {
		if rules[i].ClearFor == 0 {
			rules[i].ClearFor = 2 * time.Minute
		}
		if rules[i].Clear <= 0 || rules[i].Clear > 1 {
			rules[i].Clear = 0.95
		}
	}
	return &Engine{Rules: rules, tracks: map[string]*track{}}
}

func match(pattern, name string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(name, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == name
}

func iso(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func r2(f float64) float64 { return math.Round(f*100) / 100 }

// Observe takes one sample and returns the events it causes.
func (e *Engine) Observe(at time.Time, values map[string]float64) []Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []Event
	names := make([]string, 0, len(values))
	for n := range values {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, r := range e.Rules {
		if r.Off {
			continue
		}
		for _, n := range names {
			if !match(r.Metric, n) {
				continue
			}
			key := n
			if ev := e.step(r, key, at, values[n], true); ev != nil {
				out = append(out, *ev)
			}
		}
	}
	// A raised alert whose metric is gone (a mount removed) counts as recovered.
	for key, t := range e.tracks {
		if _, ok := values[key]; ok {
			continue
		}
		r, ok := e.rule(t.Rule)
		if !ok || r.Off {
			delete(e.tracks, key)
			continue
		}
		if ev := e.step(r, key, at, t.Last, false); ev != nil {
			out = append(out, *ev)
		}
	}
	return out
}

func (e *Engine) rule(name string) (Rule, bool) {
	for _, r := range e.Rules {
		if r.Name == name {
			return r, true
		}
	}
	return Rule{}, false
}

func (e *Engine) step(r Rule, key string, at time.Time, v float64, present bool) *Event {
	t := e.tracks[key]
	above := present && v > r.Warn
	if t == nil {
		if !above {
			return nil
		}
		t = &track{Rule: r.Name, Metric: key, WarnSince: at, Peak: v}
		e.tracks[key] = t
	}
	if present {
		t.Last = v
	}
	if above {
		t.BelowSince = time.Time{}
		if t.WarnSince.IsZero() {
			t.WarnSince = at
		}
		if v > t.Peak {
			t.Peak = v
		}
		if r.Crit > 0 && v > r.Crit {
			if t.CritSince.IsZero() {
				t.CritSince = at
			}
		} else {
			t.CritSince = time.Time{}
		}
		level := ""
		if at.Sub(t.WarnSince) >= r.For {
			level = "warn"
		}
		if !t.CritSince.IsZero() && at.Sub(t.CritSince) >= r.For {
			level = "crit"
		}
		// Raise once at warn, and once more when it escalates to crit.
		if level != "" && rank(level) > rank(t.Level) {
			t.Level = level
			return &Event{Type: "alert.raised", Ref: key, At: at, State: e.state(r, t, level, v)}
		}
		return nil
	}
	// Not above the threshold.
	if t.Level == "" {
		delete(e.tracks, key) // it never lasted long enough to raise
		return nil
	}
	t.CritSince = time.Time{}
	if present && v >= r.Warn*r.Clear {
		t.BelowSince = time.Time{} // in the hysteresis band: still raised
		return nil
	}
	if t.BelowSince.IsZero() {
		t.BelowSince = at
	}
	if at.Sub(t.BelowSince) < r.ClearFor {
		return nil
	}
	st := e.state(r, t, t.Level, t.Last)
	until := iso(at)
	d := at.Sub(t.WarnSince).Seconds()
	st.Until, st.DurationS = &until, &d
	delete(e.tracks, key)
	return &Event{Type: "alert.resolved", Ref: key, At: at, State: st}
}

func rank(level string) int {
	switch level {
	case "warn":
		return 1
	case "crit":
		return 2
	}
	return 0
}

func (e *Engine) state(r Rule, t *track, level string, v float64) State {
	th := r.Warn
	if level == "crit" {
		th = r.Crit
	}
	return State{Rule: r.Name, Metric: t.Metric, Level: level, Threshold: th, Value: r2(v), Peak: r2(t.Peak), Since: iso(t.WarnSince)}
}

// Raised lists the alerts raised now, as their latest state.
func (e *Engine) Raised() []Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []Event
	for key, t := range e.tracks {
		if t.Level == "" {
			continue
		}
		r, ok := e.rule(t.Rule)
		if !ok {
			continue
		}
		out = append(out, Event{Type: "alert.raised", Ref: key, At: t.WarnSince, State: e.state(r, t, t.Level, t.Last)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out
}

// Save is the episodes as JSON, so a restart neither forgets a raised alert
// (which would then never resolve) nor raises it twice.
func (e *Engine) Save() ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return json.Marshal(e.tracks)
}

// Load restores what Save wrote.
func (e *Engine) Load(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	m := map[string]*track{}
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	e.mu.Lock()
	e.tracks = m
	e.mu.Unlock()
	return nil
}
