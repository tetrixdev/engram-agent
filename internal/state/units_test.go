package state

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/tetrixdev/engram-agent/internal/inventory"
)

func unitsOf(t *testing.T, s Section) map[string]Unit {
	t.Helper()
	out := map[string]Unit{}
	for _, it := range s.Items {
		var u Unit
		if err := json.Unmarshal(it, &u); err != nil {
			t.Fatal(err)
		}
		out[u.Unit] = u
	}
	return out
}

func TestParseShowAndTimes(t *testing.T) {
	got := inventory.ParseShow("Id=a.timer\nUnit=a.service\nLastTriggerUSec=Wed 2026-11-11 00:00:09 UTC\n\nnoise\nId=b.service\nResult=success\n\n")
	if len(got) != 2 || got[0]["Unit"] != "a.service" || got[1]["Result"] != "success" {
		t.Fatalf("%v", got)
	}
	if tm := SystemdTime("Wed 2026-11-11 06:25:40 UTC"); tm == nil || tm.Format(time.RFC3339) != "2026-11-11T06:25:40Z" {
		t.Fatalf("time %v", tm)
	}
	for _, s := range []string{"", "n/a", "0", "yesterday"} {
		if SystemdTime(s) != nil {
			t.Fatalf("%q read as a time", s)
		}
	}
	if !inventory.ValidUnitName("nightly-db-backup.service") || !inventory.ValidUnitName("getty@tty1.service") || inventory.ValidUnitName("-p Id") || inventory.ValidUnitName("x") {
		t.Fatal("unit names")
	}
}

func TestUnitsJudgment(t *testing.T) {
	now := time.Date(2026, 11, 11, 7, 0, 0, 0, time.UTC)
	timers := []inventory.UnitProps{
		{"Id": "backup.timer", "Unit": "backup.service", "ActiveState": "active", "NextElapseUSecRealtime": "Thu 2026-11-12 03:00:00 UTC"},
		{"Id": "broken.timer", "Unit": "missing.service", "ActiveState": "failed", "Result": "resources"},
	}
	ok := inventory.UnitProps{"Id": "backup.service", "ActiveState": "inactive", "Result": "success", "ExecMainExitTimestamp": "Wed 2026-11-11 03:00:40 UTC", "ExecMainStatus": "0"}
	sec, mem := Units(timers, []inventory.UnitProps{ok}, map[string]UnitMemory{}, now, nil)
	u := unitsOf(t, sec)
	b := u["backup.service"]
	if b.Failed || b.Timer == nil || *b.Timer != "backup.timer" || b.LastSuccess == nil || *b.LastSuccess != "2026-11-11T03:00:40Z" ||
		b.NextRun == nil || *b.NextRun != "2026-11-12T03:00:00Z" || b.ExitStatus == nil || *b.ExitStatus != 0 {
		t.Fatalf("a job that succeeded: %+v", b)
	}
	if bt := u["broken.timer"]; !bt.Failed || bt.FailedSince == nil {
		t.Fatalf("a failed timer: %+v", bt)
	}
	if _, there := u["missing.service"]; there {
		t.Fatal("a service systemd did not answer for is an item")
	}
	urgent1 := sec.Urgent

	// The next night it fails: failed, the last success kept.
	failed := inventory.UnitProps{"Id": "backup.service", "ActiveState": "failed", "Result": "exit-code", "ExecMainExitTimestamp": "Thu 2026-11-12 03:00:40 UTC", "ExecMainStatus": "2", "StateChangeTimestamp": "Thu 2026-11-12 03:00:40 UTC"}
	later := now.Add(24 * time.Hour)
	sec, mem = Units(timers, []inventory.UnitProps{failed}, mem, later, nil)
	b = unitsOf(t, sec)["backup.service"]
	if !b.Failed || *b.FailedSince != "2026-11-12T03:00:40Z" || *b.LastSuccess != "2026-11-11T03:00:40Z" || *b.ExitStatus != 2 {
		t.Fatalf("a failed run: %+v", b)
	}
	if sec.Urgent == urgent1 {
		t.Fatal("a failure is not urgent")
	}
	if got := FailedNames(mem); len(got) != 2 || got[0] != "backup.service" {
		t.Fatalf("held failed: %v", got)
	}
	urgent2 := sec.Urgent

	// Run again by hand: activating, still failed since the same time.
	running := inventory.UnitProps{"Id": "backup.service", "ActiveState": "activating", "Result": "success"}
	sec, mem = Units(timers, []inventory.UnitProps{running}, mem, later.Add(time.Minute), nil)
	b = unitsOf(t, sec)["backup.service"]
	if !b.Failed || *b.FailedSince != "2026-11-12T03:00:40Z" || sec.Urgent != urgent2 {
		t.Fatalf("a re-run in progress: %+v", b)
	}

	// Reading fails: what was known stands.
	_, kept := Units(nil, nil, mem, later.Add(2*time.Minute), errors.New("systemctl: timeout"))
	if kept["backup.service"].FailedSince == "" || kept["backup.service"].LastSuccess == "" {
		t.Fatalf("a read error forgot: %+v", kept)
	}

	// It succeeds: no longer failed, a newer last success.
	done := inventory.UnitProps{"Id": "backup.service", "ActiveState": "inactive", "Result": "success", "ExecMainExitTimestamp": "Thu 2026-11-12 03:30:00 UTC", "ExecMainStatus": "0"}
	sec, mem = Units(timers, []inventory.UnitProps{done}, mem, later.Add(time.Hour), nil)
	b = unitsOf(t, sec)["backup.service"]
	if b.Failed || b.FailedSince != nil || *b.LastSuccess != "2026-11-12T03:30:00Z" {
		t.Fatalf("recovered: %+v", b)
	}

	// After a reboot systemd has no exit time: the agent's last success stands.
	boot := inventory.UnitProps{"Id": "backup.service", "ActiveState": "inactive", "Result": "success"}
	sec, _ = Units(timers, []inventory.UnitProps{boot}, mem, later.Add(2*time.Hour), nil)
	if b = unitsOf(t, sec)["backup.service"]; b.LastSuccess == nil || *b.LastSuccess != "2026-11-12T03:30:00Z" || b.LastRun != nil || b.ExitStatus != nil {
		t.Fatalf("after a reboot: %+v", b)
	}
}

func TestUnitStateKeys(t *testing.T) {
	b, _ := json.Marshal(Unit{Unit: "x.service"})
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	want := []string{"unit", "timer", "state", "result", "failed", "failed_since", "last_run", "exit_status", "last_success", "next_run"}
	if len(m) != len(want) {
		t.Fatalf("keys %v", m)
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			t.Errorf("no %s", k)
		}
	}
}
