package inventory

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// UnitProps are one unit's properties as `systemctl show` prints them,
// e.g. {"Id": "logrotate.service", "ActiveState": "inactive", ...}.
type UnitProps map[string]string

// MaxUnits is the most units one pass asks systemd about: every timer's
// service and every failed unit, so far above what a server has.
const MaxUnits = 300

// unitName is what a unit name looks like; anything else systemctl prints is
// never passed back to it.
var unitName = regexp.MustCompile(`^[A-Za-z0-9@:._\\-]{1,200}\.(service|timer|socket|mount|automount|swap|path|target|slice|scope|device)$`)

// ValidUnitName says whether s is shaped like a systemd unit name.
func ValidUnitName(s string) bool { return unitName.MatchString(s) }

// The properties read per timer and per unit.
const (
	timerProps = "Id,LoadState,ActiveState,Result,Unit,LastTriggerUSec,NextElapseUSecRealtime"
	unitProps  = "Id,LoadState,ActiveState,SubState,Result,StateChangeTimestamp,ExecMainExitTimestamp,ExecMainStatus"
)

// ParseShow reads `systemctl show` output: blocks of Key=Value lines, one
// block per unit, separated by a blank line. A block without an Id is left out.
func ParseShow(out string) []UnitProps {
	var list []UnitProps
	cur := UnitProps{}
	flush := func() {
		if cur["Id"] != "" {
			list = append(list, cur)
		}
		cur = UnitProps{}
	}
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimRight(l, "\r")
		if strings.TrimSpace(l) == "" {
			flush()
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		cur[k] = v
	}
	flush()
	return list
}

// Units asks systemd about every loaded timer, the service each one starts,
// and the units in extra (the failed ones, and those the agent still holds
// failed while they run again): their state, last result and times. Without
// root: systemd answers these to any user. Timers come first, then the
// units, each sorted by name.
func (e Env) Units(ctx context.Context, extra []string) (timers, units []UnitProps, err error) {
	out, terr := e.Run(ctx, "systemctl", "show", "--no-pager", "-p", timerProps, "*.timer")
	if terr != nil && len(out) == 0 {
		return nil, nil, fmt.Errorf("systemctl show *.timer: %w", terr)
	}
	want := map[string]bool{}
	for _, t := range ParseShow(string(out)) {
		if !ValidUnitName(t["Id"]) || t["LoadState"] == "not-found" {
			continue
		}
		timers = append(timers, t)
		if ValidUnitName(t["Unit"]) {
			want[t["Unit"]] = true
		}
	}
	for _, u := range extra {
		if ValidUnitName(u) && !strings.HasSuffix(u, ".timer") {
			want[u] = true
		}
	}
	names := make([]string, 0, len(want))
	for n := range want {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) > MaxUnits {
		names = names[:MaxUnits]
	}
	sort.Slice(timers, func(i, j int) bool { return timers[i]["Id"] < timers[j]["Id"] })
	if len(names) == 0 {
		return timers, nil, nil
	}
	args := append([]string{"show", "--no-pager", "-p", unitProps, "--"}, names...)
	out, uerr := e.Run(ctx, "systemctl", args...)
	if uerr != nil && len(out) == 0 {
		return timers, nil, fmt.Errorf("systemctl show (%d units): %w", len(names), uerr)
	}
	for _, u := range ParseShow(string(out)) {
		if want[u["Id"]] {
			units = append(units, u)
		}
	}
	sort.Slice(units, func(i, j int) bool { return units[i]["Id"] < units[j]["Id"] })
	return timers, units, nil
}
