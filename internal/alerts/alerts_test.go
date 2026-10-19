package alerts

import (
	"encoding/json"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

// feed sends one metric's values, one every 10 s from t0, and collects events.
func feed(e *Engine, metric string, values ...float64) []Event {
	var out []Event
	for i, v := range values {
		out = append(out, e.Observe(t0.Add(time.Duration(i)*10*time.Second), map[string]float64{metric: v})...)
	}
	return out
}

func repeat(v float64, n int) []float64 {
	s := make([]float64, n)
	for i := range s {
		s[i] = v
	}
	return s
}

func cat(parts ...[]float64) []float64 {
	var out []float64
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestRaisedOnlyWhenSustained(t *testing.T) {
	e := New(Defaults())
	// memory_pct over 90 for 4m50s: nothing; it drops, and the episode is forgotten.
	if evs := feed(e, "memory_pct", cat(repeat(95, 30), repeat(50, 3))...); len(evs) != 0 {
		t.Fatalf("raised before 5 minutes: %+v", evs)
	}
	e = New(Defaults())
	// 31 samples over 90 = 5 minutes from the first: raised at warn.
	evs := feed(e, "memory_pct", cat(repeat(92, 30), []float64{93})...)
	if len(evs) != 1 || evs[0].Type != "alert.raised" || evs[0].State.Level != "warn" || evs[0].State.Threshold != 90 {
		t.Fatalf("raise: %+v", evs)
	}
	st := evs[0].State
	if st.Rule != "memory_pct" || st.Metric != "memory_pct" || evs[0].Ref != "memory_pct" || st.Peak != 93 || st.Value != 93 || st.Since != "2026-10-19T12:00:00Z" {
		t.Fatalf("state %+v", st)
	}
	if st.Until != nil || st.DurationS != nil {
		t.Fatal("until/duration on a raise")
	}
}

func TestEscalatesToCrit(t *testing.T) {
	e := New(Defaults())
	// Over 97 from the start: warn and crit are reached at the same sample;
	// one event, at crit.
	evs := feed(e, "memory_pct", repeat(98, 31)...)
	if len(evs) != 1 || evs[0].State.Level != "crit" || evs[0].State.Threshold != 97 {
		t.Fatalf("%+v", evs)
	}
	// Warn first, then crit five minutes later: two raises.
	e = New(Defaults())
	evs = feed(e, "memory_pct", cat(repeat(92, 31), repeat(98, 31))...)
	if len(evs) != 2 || evs[0].State.Level != "warn" || evs[1].State.Level != "crit" || evs[1].State.Peak != 98 {
		t.Fatalf("%+v", evs)
	}
}

func TestResolvedWithHysteresis(t *testing.T) {
	e := New(Defaults())
	// Raised, then 88 (above 90*0.95 = 85.5) for 5 minutes: still raised.
	evs := feed(e, "memory_pct", cat(repeat(95, 31), repeat(88, 30))...)
	if len(evs) != 1 {
		t.Fatalf("resolved inside the hysteresis band: %+v", evs)
	}
	// Under 85.5 for less than 2 minutes, a bounce over 85.5, then under for 2 minutes: resolved once, at the end.
	e = New(Defaults())
	vals := cat(repeat(95, 31), repeat(80, 10), []float64{87}, repeat(80, 13))
	evs = feed(e, "memory_pct", vals...)
	if len(evs) != 2 || evs[1].Type != "alert.resolved" {
		t.Fatalf("%+v", evs)
	}
	r := evs[1]
	last := t0.Add(time.Duration(len(vals)-1) * 10 * time.Second)
	if !r.At.Equal(last) || *r.State.Until != last.Format(time.RFC3339) || *r.State.DurationS != last.Sub(t0).Seconds() || r.State.Peak != 95 || r.State.Level != "warn" {
		t.Fatalf("resolved %+v until %v duration %v", r.State, *r.State.Until, *r.State.DurationS)
	}
	// After that a new episode starts from nothing.
	if evs := e.Observe(last.Add(10*time.Second), map[string]float64{"memory_pct": 95}); len(evs) != 0 {
		t.Fatalf("raised at once after resolving: %+v", evs)
	}
}

func TestPerMountAndImmediate(t *testing.T) {
	e := New(Defaults())
	evs := e.Observe(t0, map[string]float64{"disk_pct:/": 50, "disk_pct:/var": 96, "inodes_pct:/var": 10})
	if len(evs) != 1 || evs[0].Ref != "disk_pct:/var" || evs[0].State.Rule != "disk_pct" || evs[0].State.Level != "crit" {
		t.Fatalf("%+v", evs)
	}
	// The mount disappears: resolved two minutes later.
	var all []Event
	for i := 1; i <= 13; i++ {
		all = append(all, e.Observe(t0.Add(time.Duration(i)*10*time.Second), map[string]float64{"disk_pct:/": 50})...)
	}
	if len(all) != 1 || all[0].Type != "alert.resolved" || all[0].Ref != "disk_pct:/var" {
		t.Fatalf("gone mount: %+v", all)
	}
}

func TestConfigure(t *testing.T) {
	rules, err := Configure(map[string]json.RawMessage{
		"cpu_pct":  json.RawMessage(`{"warn": 80, "for_s": 60}`),
		"swap_pct": json.RawMessage(`{"off": true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	e := New(rules)
	if evs := feed(e, "cpu_pct", repeat(85, 7)...); len(evs) != 1 {
		t.Fatalf("overridden cpu rule: %+v", evs)
	}
	if evs := feed(New(rules), "swap_pct", repeat(100, 100)...); len(evs) != 0 {
		t.Fatalf("a rule switched off raised: %+v", evs)
	}
	if _, err := Configure(map[string]json.RawMessage{"nope": json.RawMessage(`{}`)}); err == nil {
		t.Fatal("unknown rule accepted")
	}
}

func TestSaveLoadKeepsEpisode(t *testing.T) {
	e := New(Defaults())
	feed(e, "memory_pct", repeat(95, 31)...)
	b, err := e.Save()
	if err != nil {
		t.Fatal(err)
	}
	f := New(Defaults())
	if err := f.Load(b); err != nil {
		t.Fatal(err)
	}
	if r := f.Raised(); len(r) != 1 || r[0].Ref != "memory_pct" {
		t.Fatalf("raised after load: %+v", r)
	}
	// Still raised: another high sample sends nothing; recovery resolves it.
	at := t0.Add(400 * time.Second)
	if evs := f.Observe(at, map[string]float64{"memory_pct": 96}); len(evs) != 0 {
		t.Fatalf("raised twice: %+v", evs)
	}
	var evs []Event
	for i := 1; i <= 13; i++ {
		evs = append(evs, f.Observe(at.Add(time.Duration(i)*10*time.Second), map[string]float64{"memory_pct": 40})...)
	}
	if len(evs) != 1 || evs[0].Type != "alert.resolved" || evs[0].State.Peak != 96 {
		t.Fatalf("%+v", evs)
	}
}
