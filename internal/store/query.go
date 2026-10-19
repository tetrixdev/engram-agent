package store

import (
	"database/sql"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/tetrixdev/engram/agent/internal/collect"
)

// MaxPoints bounds what one query returns, whatever it asks for.
const MaxPoints = 2000

// Bucket is one point of a query answer.
type Bucket struct {
	T     time.Time `json:"t"`
	Avg   float64   `json:"avg"`
	P95   float64   `json:"p95"`
	Max   float64   `json:"max"`
	MaxAt time.Time `json:"max_at"`
}

// Summary is the whole range at once.
type Summary struct {
	Avg   float64    `json:"avg"`
	P95   float64    `json:"p95"`
	Max   float64    `json:"max"`
	MaxAt *time.Time `json:"max_at"`
	N     int64      `json:"samples"`
}

// Result answers one query.
type Result struct {
	Metric  string    `json:"metric"`
	Tier    string    `json:"tier"`
	Step    int64     `json:"step_s"` // seconds per returned point
	From    time.Time `json:"from"`
	To      time.Time `json:"to"`
	Points  []Bucket  `json:"points"`
	Summary Summary   `json:"summary"`
}

// ErrUnknownMetric is returned for a metric that was never recorded.
var ErrUnknownMetric = errors.New("unknown metric")

func (s *Store) metricID(name string) (int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.ids[name]
	return id, ok
}

// coverage is the oldest time tier i holds for one metric.
func (s *Store) coverage(i int, id int64) (int64, bool) {
	var t sql.NullInt64
	if i == 0 {
		_ = s.db.QueryRow(`SELECT min(t) FROM raw WHERE metric = ?`, id).Scan(&t)
	} else {
		_ = s.db.QueryRow(`SELECT min(t) FROM agg WHERE tier = ? AND metric = ?`, Tiers[i].Step, id).Scan(&t)
	}
	return t.Int64, t.Valid
}

// ChooseTier picks the tier for a range. Of the tiers that still hold data
// back to from (oldest[i]; has[i] false when the tier holds none), it takes
// the one that answers in the most points without going over `points` once
// its buckets are merged into whole groups (a tier with 180 buckets for 30
// points merges six at a time and gives 30; one with 36 merges two and gives
// 18), the coarser on a tie because it reads fewer rows. When no tier covers
// the range (it starts before history does), the coarsest that has data.
func ChooseTier(from, to int64, points int, oldest []int64, has []bool) int {
	span := to - from
	best, bestPts := -1, int64(-1)
	for i, t := range Tiers {
		if !has[i] || oldest[i] > from+t.Step {
			continue
		}
		if p := pointsFor(span, t.Step, points); p >= bestPts {
			best, bestPts = i, p
		}
	}
	if best >= 0 {
		return best
	}
	for i := len(Tiers) - 1; i >= 0; i-- {
		if has[i] {
			return i
		}
	}
	return 0
}

// groupFor is how many of a tier's buckets make one returned point.
func groupFor(span, step int64, points int) int64 {
	count := (span + step - 1) / step
	if count <= int64(points) || points <= 0 {
		return 1
	}
	return (count + int64(points) - 1) / int64(points)
}

func pointsFor(span, step int64, points int) int64 {
	count := (span + step - 1) / step
	g := groupFor(span, step, points)
	return (count + g - 1) / g
}

// Query answers a range for one metric in about `points` points.
func (s *Store) Query(metric string, from, to time.Time, points int) (*Result, error) {
	id, ok := s.metricID(metric)
	if !ok {
		return nil, fmt.Errorf("%w %q: `engram-agent status --json` lists the metrics this host records", ErrUnknownMetric, metric)
	}
	if !to.After(from) {
		return nil, errors.New("query: to must be after from")
	}
	if points <= 0 {
		points = 120
	}
	if points > MaxPoints {
		points = MaxPoints
	}
	f, t := from.Unix(), to.Unix()
	oldest := make([]int64, len(Tiers))
	has := make([]bool, len(Tiers))
	for i := range Tiers {
		oldest[i], has[i] = s.coverage(i, id)
	}
	ti := ChooseTier(f, t, points, oldest, has)
	tier := Tiers[ti]
	group := groupFor(t-f, tier.Step, points) * tier.Step
	res := &Result{Metric: metric, Tier: tier.Name, Step: group, From: from.UTC(), To: to.UTC(), Points: []Bucket{}}
	start := floorTo(f, tier.Step)
	buckets, err := s.bucketsFrom(s.db, ti, id, start, t, group)
	if err != nil {
		return nil, err
	}
	for _, b := range buckets {
		res.Points = append(res.Points, Bucket{T: time.Unix(b.T, 0).UTC(), Avg: r4(b.Avg), P95: r4(b.P95), Max: r4(b.Max), MaxAt: time.Unix(b.MaxAt, 0).UTC()})
	}
	sum, err := s.summary(ti, id, start, t)
	if err != nil {
		return nil, err
	}
	res.Summary = sum
	return res, nil
}

func r4(f float64) float64 { return math.Round(f*10000) / 10000 }

// summary is the whole range from tier i: exact from raw, from the buckets
// otherwise (the p95 then approximated as FromAggs does).
func (s *Store) summary(i int, id, from, to int64) (Summary, error) {
	var a Agg
	if i == 0 {
		pts, err := rawPoints(s.db, id, from, to)
		if err != nil {
			return Summary{}, err
		}
		a = FromRaw(from, pts)
	} else {
		kids, err := aggs(s.db, Tiers[i].Step, id, from, to)
		if err != nil {
			return Summary{}, err
		}
		a = FromAggs(from, kids)
	}
	out := Summary{N: a.N}
	if a.N > 0 {
		out.Avg, out.P95, out.Max = r4(a.Avg), r4(a.P95), r4(a.Max)
		m := time.Unix(a.MaxAt, 0).UTC()
		out.MaxAt = &m
	}
	return out, nil
}

// Peak is one high point of a metric.
type Peak struct {
	At    time.Time `json:"at"`
	Value float64   `json:"value"`
}

// MetricPeaks are the highest distinct peaks of one metric in a range.
type MetricPeaks struct {
	Metric string  `json:"metric"`
	Tier   string  `json:"tier"`
	Avg    float64 `json:"avg"`
	P95    float64 `json:"p95"`
	Max    float64 `json:"max"`
	Peaks  []Peak  `json:"peaks"`
}

// MatchMetric says whether name matches a pattern: exact, or a prefix when
// the pattern ends in '*' ("disk_pct:*", "cgroup.cpu_pct:*").
func MatchMetric(pattern, name string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(name, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == name
}

// Metrics lists the recorded metric names with data at or after since, sorted.
func (s *Store) Metrics(since int64) ([]string, error) {
	rows, err := s.db.Query(`SELECT name FROM metrics WHERE last_t >= ? ORDER BY name`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// Peaks lists, per metric matching pattern ("" for every metric), the n
// highest peaks in [from, to) that are not neighbours of a higher one.
func (s *Store) Peaks(pattern string, from, to time.Time, n int) ([]MetricPeaks, error) {
	if n <= 0 {
		n = 3
	}
	// last_t is written once a minute: reach back a little so a metric that
	// only has the last minute's samples is not skipped.
	names, err := s.Metrics(from.Unix() - 120)
	if err != nil {
		return nil, err
	}
	// Raw samples of the last minute may not be flushed to last_t yet.
	if latest, err := s.latestNames(); err == nil {
		names = mergeNames(names, latest)
	}
	out := []MetricPeaks{}
	for _, name := range names {
		if pattern != "" && !MatchMetric(pattern, name) {
			continue
		}
		mp, err := s.peaksOf(name, from, to, n)
		if err != nil {
			return nil, err
		}
		if mp != nil {
			out = append(out, *mp)
		}
	}
	return out, nil
}

func mergeNames(a, b []string) []string {
	set := map[string]bool{}
	for _, x := range a {
		set[x] = true
	}
	for _, x := range b {
		set[x] = true
	}
	out := make([]string, 0, len(set))
	for x := range set {
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}

func (s *Store) peaksOf(name string, from, to time.Time, n int) (*MetricPeaks, error) {
	id, ok := s.metricID(name)
	if !ok {
		return nil, nil
	}
	f, t := from.Unix(), to.Unix()
	oldest := make([]int64, len(Tiers))
	has := make([]bool, len(Tiers))
	for i := range Tiers {
		oldest[i], has[i] = s.coverage(i, id)
	}
	// Fine enough to tell peaks apart: at least 1000 buckets when the range allows.
	ti := ChooseTier(f, t, 1000, oldest, has)
	step := Tiers[ti].Step
	buckets, err := s.bucketsFrom(s.db, ti, id, floorTo(f, step), t, step)
	if err != nil {
		return nil, err
	}
	if len(buckets) == 0 {
		return nil, nil
	}
	sum, err := s.summary(ti, id, floorTo(f, step), t)
	if err != nil {
		return nil, err
	}
	sorted := append([]Agg(nil), buckets...)
	sort.SliceStable(sorted, func(a, b int) bool { return sorted[a].Max > sorted[b].Max })
	mp := &MetricPeaks{Metric: name, Tier: Tiers[ti].Name, Avg: sum.Avg, P95: sum.P95, Max: sum.Max, Peaks: []Peak{}}
	var chosen []int64
	for _, b := range sorted {
		if len(mp.Peaks) >= n {
			break
		}
		near := false
		for _, c := range chosen {
			if d := b.T - c; d <= step && d >= -step {
				near = true
				break
			}
		}
		if near {
			continue
		}
		chosen = append(chosen, b.T)
		mp.Peaks = append(mp.Peaks, Peak{At: time.Unix(b.MaxAt, 0).UTC(), Value: r4(b.Max)})
	}
	return mp, nil
}

// Latest is the newest raw sample: its time and every value in it.
func (s *Store) Latest() (time.Time, map[string]float64, error) {
	var t sql.NullInt64
	if err := s.db.QueryRow(`SELECT max(t) FROM raw WHERE metric = (SELECT id FROM metrics WHERE name = 'load1')`).Scan(&t); err != nil {
		return time.Time{}, nil, err
	}
	if !t.Valid {
		if err := s.db.QueryRow(`SELECT max(t) FROM raw`).Scan(&t); err != nil || !t.Valid {
			return time.Time{}, map[string]float64{}, err
		}
	}
	vals, err := s.valuesAt(t.Int64)
	return time.Unix(t.Int64, 0).UTC(), vals, err
}

func (s *Store) valuesAt(t int64) (map[string]float64, error) {
	// raw's key leads with the metric, so this visits each metric's range.
	rows, err := s.db.Query(`SELECT m.name, r.v FROM metrics m JOIN raw r ON r.metric = m.id AND r.t = ?`, t)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]float64{}
	for rows.Next() {
		var n string
		var v int64
		if err := rows.Scan(&n, &v); err != nil {
			return nil, err
		}
		out[n] = dec(v)
	}
	return out, rows.Err()
}

func (s *Store) latestNames() ([]string, error) {
	_, vals, err := s.Latest()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(vals))
	for n := range vals {
		out = append(out, n)
	}
	return out, nil
}

// TopSample is the top processes at one sample.
type TopSample struct {
	At    time.Time      `json:"at"`
	ByCPU []collect.Proc `json:"by_cpu"`
	ByMem []collect.Proc `json:"by_memory"`
}

// Top returns the top-process sample nearest to at (the latest when at is zero).
func (s *Store) Top(at time.Time) (*TopSample, error) {
	var t sql.NullInt64
	var err error
	if at.IsZero() {
		err = s.db.QueryRow(`SELECT max(t) FROM top`).Scan(&t)
	} else {
		a := at.Unix()
		// The nearest on either side, each found through the key.
		var before, after sql.NullInt64
		_ = s.db.QueryRow(`SELECT max(t) FROM top WHERE t <= ?`, a).Scan(&before)
		_ = s.db.QueryRow(`SELECT min(t) FROM top WHERE t > ?`, a).Scan(&after)
		switch {
		case before.Valid && after.Valid:
			if a-before.Int64 <= after.Int64-a {
				t = before
			} else {
				t = after
			}
		case before.Valid:
			t = before
		default:
			t = after
		}
	}
	if err != nil {
		return nil, err
	}
	if !t.Valid {
		return nil, errors.New("no process samples recorded yet")
	}
	rows, err := s.db.Query(`SELECT by, pid, comm, uid, cpu_pct, rss FROM top WHERE t = ? ORDER BY by, rank`, t.Int64)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := &TopSample{At: time.Unix(t.Int64, 0).UTC(), ByCPU: []collect.Proc{}, ByMem: []collect.Proc{}}
	for rows.Next() {
		var by string
		var p collect.Proc
		var rss int64
		if err := rows.Scan(&by, &p.PID, &p.Comm, &p.UID, &p.CPUPct, &rss); err != nil {
			return nil, err
		}
		p.RSS = uint64(rss)
		if by == "cpu" {
			out.ByCPU = append(out.ByCPU, p)
		} else {
			out.ByMem = append(out.ByMem, p)
		}
	}
	return out, rows.Err()
}
