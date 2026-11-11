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
	ok := inventory.UnitProps{"Id": "backup.service", "ActiveState": "inactive", "Result": "success", "ExecMainExitTimestamp": "Wed 2026-11-11 03:00:40 UTC", "ExecMainCode": "1", "ExecMainStatus": "0"}
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

	// Run again by hand: activating, still failed since the same time, and
	// still reported with the failed run's result and exit.
	running := inventory.UnitProps{"Id": "backup.service", "ActiveState": "activating", "Result": "success"}
	sec, mem = Units(timers, []inventory.UnitProps{running}, mem, later.Add(time.Minute), nil)
	b = unitsOf(t, sec)["backup.service"]
	if !b.Failed || *b.FailedSince != "2026-11-12T03:00:40Z" || sec.Urgent != urgent2 || b.Result != "exit-code" || b.ExitStatus == nil || *b.ExitStatus != 2 {
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

	// reset-failed: Result success, but the exit is the failed run's: no
	// success recorded, and the failure is cleared (a person reset it).
	failed2 := inventory.UnitProps{"Id": "backup.service", "ActiveState": "failed", "Result": "exit-code", "ExecMainExitTimestamp": "Fri 2026-11-13 03:00:40 UTC", "ExecMainCode": "1", "ExecMainStatus": "2", "StateChangeTimestamp": "Fri 2026-11-13 03:00:40 UTC"}
	_, m2 := Units(timers, []inventory.UnitProps{failed2}, mem, later.Add(25*time.Hour), nil)
	reset := inventory.UnitProps{"Id": "backup.service", "ActiveState": "inactive", "Result": "success", "ExecMainExitTimestamp": "Fri 2026-11-13 03:00:40 UTC", "ExecMainCode": "1", "ExecMainStatus": "2", "StateChangeTimestamp": "Fri 2026-11-13 09:00:00 UTC"}
	sec, m3 := Units(timers, []inventory.UnitProps{reset}, m2, later.Add(26*time.Hour), nil)
	if b = unitsOf(t, sec)["backup.service"]; b.Failed || *b.LastSuccess != "2026-11-12T03:30:00Z" {
		t.Fatalf("after reset-failed: %+v", b)
	}
	// A reboot after a failure: inactive, no exit time: still failed until it runs.
	_, m4 := Units(timers, []inventory.UnitProps{failed2}, m3, later.Add(27*time.Hour), nil)
	booted := inventory.UnitProps{"Id": "backup.service", "ActiveState": "inactive", "Result": "success"}
	sec, _ = Units(timers, []inventory.UnitProps{booted}, m4, later.Add(28*time.Hour), nil)
	if b = unitsOf(t, sec)["backup.service"]; !b.Failed {
		t.Fatalf("a reboot cleared a failure: %+v", b)
	}
	// A job whose SuccessExitStatus= allows exit 24: systemd says success, so it is one.
	ok24 := inventory.UnitProps{"Id": "rsync.service", "ActiveState": "inactive", "Result": "success", "ExecMainExitTimestamp": "Sat 2026-11-14 03:00:00 UTC", "ExecMainCode": "1", "ExecMainStatus": "24", "StateChangeTimestamp": "Sat 2026-11-14 03:00:00 UTC"}
	if sec, _ := Units(nil, []inventory.UnitProps{ok24}, nil, later.Add(30*time.Hour), nil); unitsOf(t, sec)["rsync.service"].LastSuccess == nil {
		t.Fatal("a success by SuccessExitStatus was not one")
	}
	// A unit gone (its file removed): no item, memory dropped.
	gone := inventory.UnitProps{"Id": "backup.service", "LoadState": "not-found", "ActiveState": "inactive", "Result": "success"}
	sec, m5 := Units(nil, []inventory.UnitProps{gone}, m4, later.Add(29*time.Hour), nil)
	if len(sec.Items) != 0 || len(m5) != 0 {
		t.Fatalf("a gone unit: %s %v", sec.Items, m5)
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
