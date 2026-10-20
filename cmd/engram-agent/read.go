package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/tetrixdev/engram-agent/internal/config"
	"github.com/tetrixdev/engram-agent/internal/store"
)

// now is the clock of every command; tests replace it.
var now = time.Now

type common struct {
	config *string
	db     *string
	json   *bool
}

func commonFlags(fs *flag.FlagSet) common {
	return common{
		config: fs.String("config", config.DefaultPath, "configuration file (optional)"),
		db:     fs.String("db", "", "history file (default from the configuration: /var/lib/engram-agent/history.db)"),
		json:   fs.Bool("json", false, "answer as JSON"),
	}
}

func (c common) load() (*config.Config, error) {
	cfg, err := config.Load(*c.config)
	if err != nil {
		return nil, err
	}
	if *c.db != "" {
		cfg.DB = *c.db
	}
	return cfg, nil
}

func (c common) openRead() (*store.Store, *config.Config, error) {
	cfg, err := c.load()
	if err != nil {
		return nil, nil, c.wrap(err)
	}
	if _, err := os.Stat(cfg.DB); err != nil {
		return nil, nil, c.wrap(fmt.Errorf("cannot read %s (%v): is engram-agent running, and are you in group engram-agent?", cfg.DB, err))
	}
	s, err := store.OpenReadOnly(cfg.DB)
	if err != nil {
		return nil, nil, c.wrap(err)
	}
	return s, cfg, nil
}

func (c common) wrap(err error) error {
	if err == nil || !*c.json {
		return err
	}
	return jsonErr{err}
}

// ParseTime reads a moment: "now", RFC 3339 ("2026-10-19T14:05:00Z"), a
// date-time without zone (read as UTC), unix seconds, or a duration back from
// now ("-1h", "90m", "2d"; the sign is optional).
func ParseTime(s string, ref time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	switch {
	case s == "" || s == "now":
		return ref, nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 100000000 {
		return time.Unix(n, 0).UTC(), nil
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02T15:04", "2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	d := strings.TrimPrefix(s, "-")
	if strings.HasSuffix(d, "d") {
		if n, err := strconv.ParseFloat(strings.TrimSuffix(d, "d"), 64); err == nil {
			return ref.Add(-time.Duration(n * float64(24*time.Hour))), nil
		}
	}
	if dur, err := time.ParseDuration(d); err == nil {
		return ref.Add(-dur), nil
	}
	return time.Time{}, fmt.Errorf("cannot read time %q: use RFC 3339 (2026-10-19T14:05:00Z), unix seconds, or a duration back from now (-1h, 2d)", s)
}

// QueryRequest is the JSON a `query` takes.
type QueryRequest struct {
	Metric string `json:"metric"`
	From   string `json:"from"`
	To     string `json:"to"`
	Points int    `json:"points"`
}

func cmdQuery(args []string, out, errOut io.Writer) error {
	fs := newFlags("query", errOut)
	c := commonFlags(fs)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return c.wrap(errors.New(`give the request as one JSON argument: query --json '{"metric":"cpu_pct","from":"-6h","to":"now","points":120}'`))
	}
	var req QueryRequest
	dec := json.NewDecoder(strings.NewReader(pos[0]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return c.wrap(fmt.Errorf("the request is not the JSON expected ({metric, from, to, points}): %v", err))
	}
	if req.Metric == "" {
		return c.wrap(errors.New("the request needs a metric"))
	}
	ref := now()
	if req.From == "" {
		req.From = "-1h"
	}
	from, err := ParseTime(req.From, ref)
	if err != nil {
		return c.wrap(err)
	}
	to, err := ParseTime(req.To, ref)
	if err != nil {
		return c.wrap(err)
	}
	s, _, err := c.openRead()
	if err != nil {
		return err
	}
	defer s.Close()
	res, err := s.Query(req.Metric, from, to, req.Points)
	if err != nil {
		return c.wrap(err)
	}
	if *c.json {
		return writeJSON(out, res)
	}
	fmt.Fprintf(out, "%s, %s to %s, tier %s, %ds per point\n", res.Metric, res.From.Format(time.RFC3339), res.To.Format(time.RFC3339), res.Tier, res.Step)
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "time\tavg\tp95\tmax")
	for _, p := range res.Points {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p.T.Format(time.RFC3339), trimFloat(p.Avg), trimFloat(p.P95), trimFloat(p.Max))
	}
	tw.Flush()
	if res.Summary.MaxAt != nil {
		fmt.Fprintf(out, "summary: avg %s, p95 %s, max %s at %s\n", trimFloat(res.Summary.Avg), trimFloat(res.Summary.P95), trimFloat(res.Summary.Max), res.Summary.MaxAt.Format(time.RFC3339))
	}
	return nil
}

func cmdPeaks(args []string, out, errOut io.Writer) error {
	fs := newFlags("peaks", errOut)
	c := commonFlags(fs)
	fromS := fs.String("from", "-1h", "start of the range")
	toS := fs.String("to", "now", "end of the range")
	metric := fs.String("metric", "", "one metric, or a prefix ending in * (disk_pct:*); default every metric")
	n := fs.Int("n", 3, "peaks per metric")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	ref := now()
	from, err := ParseTime(*fromS, ref)
	if err != nil {
		return c.wrap(err)
	}
	to, err := ParseTime(*toS, ref)
	if err != nil {
		return c.wrap(err)
	}
	s, _, err := c.openRead()
	if err != nil {
		return err
	}
	defer s.Close()
	peaks, err := s.Peaks(*metric, from, to, *n)
	if err != nil {
		return c.wrap(err)
	}
	if *c.json {
		return writeJSON(out, map[string]any{"from": from.UTC(), "to": to.UTC(), "metrics": peaks})
	}
	printPeaks(out, peaks)
	return nil
}

func printPeaks(out io.Writer, peaks []store.MetricPeaks) {
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "metric\tavg\tp95\tmax\tpeaks")
	for _, m := range peaks {
		var ps []string
		for _, p := range m.Peaks {
			ps = append(ps, fmt.Sprintf("%s at %s", trimFloat(p.Value), p.At.Local().Format("15:04:05")))
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", m.Metric, trimFloat(m.Avg), trimFloat(m.P95), trimFloat(m.Max), strings.Join(ps, ", "))
	}
	tw.Flush()
}

func cmdTop(args []string, out, errOut io.Writer) error {
	fs := newFlags("top", errOut)
	c := commonFlags(fs)
	atS := fs.String("at", "", "the moment (default the latest sample)")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	var at time.Time
	if *atS != "" {
		var err error
		if at, err = ParseTime(*atS, now()); err != nil {
			return c.wrap(err)
		}
	}
	s, _, err := c.openRead()
	if err != nil {
		return err
	}
	defer s.Close()
	top, err := s.Top(at)
	if err != nil {
		return c.wrap(err)
	}
	if *c.json {
		return writeJSON(out, top)
	}
	fmt.Fprintf(out, "sample of %s\n", top.At.Local().Format(time.RFC3339))
	for _, part := range []struct {
		title string
		list  any
	}{{"by cpu", top.ByCPU}, {"by memory", top.ByMem}} {
		fmt.Fprintf(out, "\n%s\n", part.title)
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "pid\tuid\tcpu %\trss MB\tcommand")
		list := top.ByCPU
		if part.title == "by memory" {
			list = top.ByMem
		}
		for _, p := range list {
			fmt.Fprintf(tw, "%d\t%d\t%s\t%s\t%s\n", p.PID, p.UID, trimFloat(p.CPUPct), trimFloat(float64(p.RSS)/(1<<20)), p.Comm)
		}
		tw.Flush()
	}
	return nil
}

func cmdMetrics(args []string, out, errOut io.Writer) error {
	fs := newFlags("metrics", errOut)
	c := commonFlags(fs)
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	s, _, err := c.openRead()
	if err != nil {
		return err
	}
	defer s.Close()
	names, err := s.Metrics(-1 << 62)
	if err != nil {
		return c.wrap(err)
	}
	if *c.json {
		return writeJSON(out, map[string]any{"metrics": names})
	}
	for _, n := range names {
		fmt.Fprintln(out, n)
	}
	return nil
}

// coreMetrics are what `status` shows first, in this order.
var coreMetrics = []string{"cpu_pct", "load1", "load5", "load15", "memory_pct", "swap_pct",
	"pressure.cpu_some", "pressure.memory_some", "pressure.memory_full", "pressure.io_some", "pressure.io_full",
	"net_rx_bps", "net_tx_bps"}

// Status is what `status --json` answers.
type Status struct {
	Version   string              `json:"agent_version"`
	DB        string              `json:"db"`
	DBBytes   int64               `json:"db_bytes"`
	SampleAt  *time.Time          `json:"sample_at"`
	Now       map[string]float64  `json:"now"`
	LastHour  []store.MetricPeaks `json:"last_hour"`
	Enrolment Enrolment           `json:"enrolment"`
}

// Enrolment says whether this agent reports to an Engram.
type Enrolment struct {
	Enrolled    bool   `json:"enrolled"`
	URL         string `json:"url,omitempty"`
	AgentID     string `json:"agent_id,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Report      string `json:"report_state,omitempty"` // ok, retrying, removed, unauthorized, clock, not_enrolled
	LastReport  string `json:"last_report,omitempty"`  // when Engram last accepted a report
	Note        string `json:"note,omitempty"`
}

func cmdStatus(args []string, out, errOut io.Writer) error {
	fs := newFlags("status", errOut)
	c := commonFlags(fs)
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	s, cfg, err := c.openRead()
	if err != nil {
		return err
	}
	defer s.Close()
	st := Status{Version: Version, DB: cfg.DB, Now: map[string]float64{}, Enrolment: enrolmentOf(cfg, s.Meta)}
	for _, f := range []string{cfg.DB, cfg.DB + "-wal"} {
		if fi, err := os.Stat(f); err == nil {
			st.DBBytes += fi.Size()
		}
	}
	at, vals, err := s.Latest()
	if err != nil {
		return c.wrap(err)
	}
	if !at.IsZero() {
		st.SampleAt = &at
		st.Now = vals
	}
	ref := now()
	var hour []store.MetricPeaks
	for _, pattern := range append(append([]string{}, coreMetrics...), "disk_pct:*", "inodes_pct:*") {
		p, err := s.Peaks(pattern, ref.Add(-time.Hour), ref, 1)
		if err != nil {
			return c.wrap(err)
		}
		hour = append(hour, p...)
	}
	st.LastHour = hour
	if *c.json {
		return writeJSON(out, st)
	}
	printStatus(out, st)
	return nil
}

func printStatus(out io.Writer, st Status) {
	fmt.Fprintf(out, "engram-agent %s\n", st.Version)
	e := st.Enrolment
	if e.Enrolled {
		fmt.Fprintf(out, "enrolled with %s as %s\nfingerprint %s\n", e.URL, e.AgentID, e.Fingerprint)
		rs := e.Report
		if rs == "" {
			rs = "no report yet"
		}
		if e.LastReport != "" {
			rs += ", last accepted " + e.LastReport
		}
		fmt.Fprintf(out, "reporting: %s\n", rs)
		if e.Note != "" {
			fmt.Fprintf(out, "  %s\n", e.Note)
		}
	} else {
		fmt.Fprintf(out, "%s\n", e.Note)
	}
	fmt.Fprintf(out, "history %s (%s MB)\n", st.DB, trimFloat(float64(st.DBBytes)/(1<<20)))
	if st.SampleAt == nil {
		fmt.Fprintln(out, "\nno samples yet")
		return
	}
	fmt.Fprintf(out, "\nnow (%s)\n", st.SampleAt.Local().Format("15:04:05"))
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	for _, m := range coreMetrics {
		if v, ok := st.Now[m]; ok {
			fmt.Fprintf(tw, "  %s\t%s\n", m, trimFloat(v))
		}
	}
	var disks []string
	for k := range st.Now {
		if strings.HasPrefix(k, "disk_pct:") || strings.HasPrefix(k, "inodes_pct:") {
			disks = append(disks, k)
		}
	}
	sort.Strings(disks)
	for _, k := range disks {
		fmt.Fprintf(tw, "  %s\t%s\n", k, trimFloat(st.Now[k]))
	}
	tw.Flush()
	fmt.Fprintln(out, "\nlast hour")
	printPeaks(out, st.LastHour)
}
