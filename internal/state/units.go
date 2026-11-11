package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tetrixdev/engram-agent/internal/inventory"
)

// UnitsMinInterval is how often at most a section with an Urgent digest (the
// units) goes when only its times changed (a timer ran, the next run moved): a server with a timer
// every few minutes would otherwise send it with every inventory. A unit
// failing or recovering goes at once (see Section.Urgent).
const UnitsMinInterval = time.Hour

// Unit is one item of the units section: a service a timer starts (a job),
// a unit that failed, or a timer that failed. Its keys are the ones the
// Servers app declares for the section.
type Unit struct {
	Unit string `json:"unit"`
	// Timer is the timer that starts it, or null.
	Timer *string `json:"timer"`
	// State is systemd's ActiveState now: active, inactive, failed,
	// activating, deactivating, reloading.
	State string `json:"state"`
	// Result is systemd's Result of the last run: success, exit-code,
	// signal, timeout, core-dump, start-limit-hit, ...
	Result string `json:"result"`
	// Failed is the agent's judgment: the unit failed and has not run
	// successfully since. It stays true while a new run is in progress, so a
	// job that fails, runs again and fails again is one failure, not three.
	Failed bool `json:"failed"`
	// FailedSince is when the agent first saw it failed (RFC 3339), or null.
	FailedSince *string `json:"failed_since"`
	// LastRun is when its last run ended (ExecMainExitTimestamp), or null.
	LastRun *string `json:"last_run"`
	// ExitStatus is the main process's exit status of that run, or null.
	ExitStatus *int `json:"exit_status"`
	// LastSuccess is the last time the agent saw a run of it end in success,
	// kept by the agent across reboots (systemd forgets on boot), or null.
	LastSuccess *string `json:"last_success"`
	// NextRun is when its timer runs next (wall clock), or null.
	NextRun *string `json:"next_run"`
}

// UnitMemory is what the agent keeps per unit between passes.
type UnitMemory struct {
	FailedSince  string `json:"failed_since,omitempty"`  // RFC 3339; "" while not failed
	FailedResult string `json:"failed_result,omitempty"` // systemd's Result of the failed run
	FailedExit   *int   `json:"failed_exit,omitempty"`   // its main process's exit status, if known
	LastSuccess  string `json:"last_success,omitempty"`  // RFC 3339; "" when never seen
}

// inProgress are the ActiveStates of a run still going on.
var inProgress = map[string]bool{"activating": true, "deactivating": true, "reloading": true, "refreshing": true}

// SystemdTime reads a time as `systemctl show` prints it with TZ=UTC
// ("Wed 2026-11-11 06:25:40 UTC"); empty, "n/a" or anything else is nil.
func SystemdTime(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" || s == "n/a" || s == "0" {
		return nil
	}
	for _, layout := range []string{"Mon 2006-01-02 15:04:05 MST", "Mon 2006-01-02 15:04:05.000000 MST"} {
		if t, err := time.Parse(layout, s); err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}

func rfc(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format(time.RFC3339)
	return &s
}

func strOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Units judges what systemd said (inventory.Env.Units) against what the
// agent kept from earlier passes, and returns the units section and the
// memory to keep. A unit is in the section when a timer starts it, when it
// failed, or while it is still held failed; memory of a unit no longer
// there is dropped.
func Units(timers, units []inventory.UnitProps, mem map[string]UnitMemory, now time.Time, readErr error) (Section, map[string]UnitMemory) {
	next := map[string]UnitMemory{}
	timerOf := map[string]inventory.UnitProps{}
	var items []Unit
	for _, t := range timers {
		if u := t["Unit"]; u != "" {
			if _, dup := timerOf[u]; !dup {
				timerOf[u] = t
			}
		}
		// A timer is an item of its own only when the timer itself failed
		// (its service missing, a start limit): a job's runs are its service's.
		if t["ActiveState"] == "failed" || mem[t["Id"]].FailedSince != "" && inProgress[t["ActiveState"]] {
			m := mem[t["Id"]]
			if m.FailedSince == "" {
				m.FailedSince = now.UTC().Format(time.RFC3339)
				if at := SystemdTime(t["StateChangeTimestamp"]); t["ActiveState"] == "failed" && at != nil && !at.After(now) {
					m.FailedSince = at.Format(time.RFC3339)
				}
			}
			next[t["Id"]] = m
			items = append(items, Unit{Unit: t["Id"], State: t["ActiveState"], Result: t["Result"], Failed: true, FailedSince: strOrNil(m.FailedSince)})
		}
	}
	for _, u := range units {
		id := u["Id"]
		if u["LoadState"] == "not-found" {
			continue // gone: no item, and its memory is dropped
		}
		m := mem[id]
		st := u["ActiveState"]
		lastRun := SystemdTime(u["ExecMainExitTimestamp"])
		heldSince := m.FailedSince
		// Held failed while it runs again, and after a reboot until it has
		// run (inactive, no exit time and no state change since boot:
		// systemd forgot the failed run). A run that ends without failing,
		// active (running), a reset-failed (which stamps a state change) or
		// a unit file gone clears it.
		rebooted := st == "inactive" && lastRun == nil && SystemdTime(u["StateChangeTimestamp"]) == nil
		failed := st == "failed" || (heldSince != "" && (inProgress[st] || rebooted))
		if failed {
			if m.FailedSince == "" {
				// When systemd says it entered the failed state, else now.
				m.FailedSince = now.UTC().Format(time.RFC3339)
				if at := SystemdTime(u["StateChangeTimestamp"]); st == "failed" && at != nil && !at.After(now) {
					m.FailedSince = at.Format(time.RFC3339)
				}
			}
			if st == "failed" {
				m.FailedResult, m.FailedExit = u["Result"], nil
				if n, err := strconv.Atoi(u["ExecMainStatus"]); err == nil && lastRun != nil {
					m.FailedExit = &n
				}
			}
		} else {
			m.FailedSince, m.FailedResult, m.FailedExit = "", "", nil
		}
		// A success is a run systemd counts as one (Result success, which
		// honours SuccessExitStatus=) that ended after any failure held
		// before: after a reset-failed the result reads success over the
		// failed run's exit, which is not after the failure.
		afterFailure := true
		if at, err := time.Parse(time.RFC3339, heldSince); err == nil && lastRun != nil && !lastRun.After(at) {
			afterFailure = false
		}
		if !failed && u["Result"] == "success" && lastRun != nil && afterFailure {
			if prev, err := time.Parse(time.RFC3339, m.LastSuccess); err != nil || lastRun.After(prev) {
				m.LastSuccess = lastRun.Format(time.RFC3339)
			}
		}
		it := Unit{Unit: id, State: st, Result: u["Result"], Failed: failed, FailedSince: strOrNil(m.FailedSince),
			LastRun: rfc(lastRun), LastSuccess: strOrNil(m.LastSuccess)}
		if n, err := strconv.Atoi(u["ExecMainStatus"]); err == nil && lastRun != nil {
			it.ExitStatus = &n
		}
		if failed && st != "failed" && m.FailedResult != "" {
			// Held through a re-run or a reboot: systemd has reset the
			// result and exit; report the failed run's, so what Engram shows
			// of the failure does not change until it is over.
			it.Result, it.ExitStatus = m.FailedResult, m.FailedExit
		}
		if t, ok := timerOf[id]; ok {
			tn := t["Id"]
			it.Timer = &tn
			it.NextRun = rfc(SystemdTime(t["NextElapseUSecRealtime"]))
		}
		next[id] = m
		items = append(items, it)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Unit < items[j].Unit })
	if readErr != nil {
		// Nothing could be read: keep what was known, so a failure is not
		// taken for a recovery and a last success is not forgotten.
		next = mem
	}
	return Section{Name: "units", CollectedAt: now, Items: Raw(items), Meta: RawMeta(nil), Error: errp(readErr), Urgent: urgentOf(items, readErr)}, next
}

// FailedNames are the units the memory holds failed: asked about again next
// pass even when `systemctl --failed` no longer lists them (a new run).
func FailedNames(mem map[string]UnitMemory) []string {
	var out []string
	for n, m := range mem {
		if m.FailedSince != "" {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// urgentOf is the digest of what must reach Engram at once: which units are
// there and which of them are failed, and whether reading worked.
func urgentOf(items []Unit, err error) string {
	var b strings.Builder
	for _, it := range items {
		b.WriteString(it.Unit)
		if it.Failed {
			b.WriteString(":failed")
		}
		b.WriteString("\n")
	}
	if err != nil {
		b.WriteString("error\n")
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// UnitsMemory reads the kept memory; anything unreadable is an empty one.
func UnitsMemory(raw string) map[string]UnitMemory {
	m := map[string]UnitMemory{}
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &m)
	}
	return m
}
