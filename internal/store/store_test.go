package store

import (
	"math"
	"path/filepath"
	"testing"
	"time"

	"github.com/tetrixdev/engram-agent/internal/collect"
)

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestPercentile(t *testing.T) {
	cases := []struct {
		vals []float64
		q    float64
		want float64
	}{
		{[]float64{5}, 0.95, 5},
		{[]float64{1, 2, 3, 4, 5, 6}, 0.95, 5.75}, // h = 4.75: between 5 and 6
		{[]float64{6, 1, 5, 2, 4, 3}, 0.5, 3.5},
		{[]float64{10, 10, 10}, 0.95, 10},
		{nil, 0.95, 0},
	}
	for _, c := range cases {
		if got := Percentile(c.vals, c.q); !near(got, c.want) {
			t.Errorf("Percentile(%v, %v) = %v, want %v", c.vals, c.q, got, c.want)
		}
	}
}

func TestFromRaw(t *testing.T) {
	a := FromRaw(60, []Point{{60, 1}, {70, 2}, {80, 9}, {90, 3}, {100, 4}, {110, 5}})
	if a.N != 6 || !near(a.Avg, 4) || a.Max != 9 || a.MaxAt != 80 || !near(a.P95, 8) {
		t.Fatalf("FromRaw = %+v", a)
	}
}

func TestFromAggs(t *testing.T) {
	// Steady load: the approximation is exact.
	steady := []Agg{{N: 6, Avg: 50, P95: 50, Max: 50, MaxAt: 10}, {N: 6, Avg: 50, P95: 50, Max: 50, MaxAt: 70}}
	a := FromAggs(0, steady)
	if a.N != 12 || a.Avg != 50 || a.P95 != 50 || a.Max != 50 || a.MaxAt != 10 {
		t.Fatalf("steady = %+v", a)
	}
	// The mean is weighted by samples; max and max_at come from the highest child.
	kids := []Agg{{N: 2, Avg: 10, P95: 12, Max: 13, MaxAt: 5}, {N: 6, Avg: 20, P95: 30, Max: 90, MaxAt: 77}, {N: 4, Avg: 5, P95: 6, Max: 7, MaxAt: 130}}
	a = FromAggs(0, kids)
	if a.N != 12 || !near(a.Avg, (20.0+120+20)/12) || a.Max != 90 || a.MaxAt != 77 {
		t.Fatalf("mixed = %+v", a)
	}
	if a.P95 > a.Max || a.P95 < 6 || a.P95 > 30 {
		t.Fatalf("p95 %v outside the children's p95s", a.P95)
	}
	// A zero-sample child is ignored.
	if b := FromAggs(0, []Agg{{N: 0, Max: 1000}}); b.N != 0 || b.Max != 0 {
		t.Fatalf("empty = %+v", b)
	}
}

func TestWeightedPercentile(t *testing.T) {
	// One value is all there is.
	if got := WeightedPercentile([]float64{7}, []float64{3}, 0.95); got != 7 {
		t.Fatal(got)
	}
	// Twelve equal weights: positions (i-0.5)/12; 0.95 lies 90 % of the way from the 11th to the 12th.
	vals := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	w := make([]float64, 12)
	for i := range w {
		w[i] = 1
	}
	if got := WeightedPercentile(vals, w, 0.95); !near(got, 11.9) {
		t.Fatalf("equal weights: %v", got)
	}
	// A heavy low value pulls it down: 90 % of the weight at 1.
	if got := WeightedPercentile([]float64{1, 100}, []float64{9, 1}, 0.95); got != 100 {
		t.Fatalf("heavy low: %v (0.95 is past the last midpoint 0.95)", got)
	}
	if got := WeightedPercentile([]float64{1, 100}, []float64{19, 1}, 0.9); !near(got, 1+(0.9-0.475)/(0.975-0.475)*99) {
		t.Fatalf("interpolated: %v", got)
	}
}

func TestChooseTier(t *testing.T) {
	now := int64(400 * 86400)
	all := []bool{true, true, true, true}
	oldest := []int64{now - 48*3600, now - 14*86400, now - 90*86400, now - 396*86400}
	cases := []struct {
		name   string
		from   int64
		points int
		want   string
	}{
		{"last 10 minutes, 120 points: only raw gives 60, the finest covering", now - 600, 120, "10s"},
		{"last 2 hours, 120 points: raw and 1m both give 120, 1m is coarser", now - 7200, 120, "1m"},
		{"last 6 hours, 120 points: 1m gives 360 (5m only 72)", now - 6*3600, 120, "1m"},
		{"last 3 days, 120 points: raw is gone, 1m merges 36 into 120 points, 5m only 108", now - 3*86400, 120, "1m"},
		{"last 30 days, 120 points: 5m and 1h both give 120, 1h is coarser", now - 30*86400, 120, "1h"},
		{"last 30 days, 1000 points: 5m gives 960, 1h only 720", now - 30*86400, 1000, "5m"},
		{"two years: nothing covers it, the coarsest that has data", now - 730*86400, 120, "1h"},
	}
	for _, c := range cases {
		if got := Tiers[ChooseTier(c.from, now, c.points, oldest, all)].Name; got != c.want {
			t.Errorf("%s: got %s", c.name, got)
		}
	}
	// A young agent: only an hour of raw. A 6-hour range still answers from raw.
	young := []int64{now - 3600, now - 3540, 0, 0}
	if got := Tiers[ChooseTier(now-6*3600, now, 120, young, []bool{true, true, false, false})].Name; got != "1m" {
		t.Errorf("young agent: %s", got)
	}
}

func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// bulk writes raw samples for metrics every step seconds in [from, to),
// in one transaction, with value f(metric index, t).
func bulk(t *testing.T, s *Store, names []string, from, to, step int64, f func(i int, t int64) float64) {
	t.Helper()
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i, n := range names {
		id, err := s.idTx(tx, n)
		if err != nil {
			t.Fatal(err)
		}
		for ts := from; ts < to; ts += step {
			if _, err := tx.Exec(`INSERT INTO raw (metric, t, v) VALUES (?, ?, ?)`, id, ts, enc(f(i, ts))); err != nil {
				t.Fatal(err)
			}
		}
		s.seen[id] = to - step
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestRollupAndQuery(t *testing.T) {
	s := openTemp(t)
	base := int64(1_800_000_000) // a whole hour: 1_800_000_000 % 3600 == 0
	if base%3600 != 0 {
		t.Fatal("base must be on the hour")
	}
	// Three hours of cpu_pct: 10 everywhere, and one spike of 95 at base+3605.
	bulk(t, s, []string{"cpu_pct"}, base, base+3*3600, 10, func(_ int, ts int64) float64 {
		if ts == base+3605-5 {
			return 95
		}
		return 10
	})
	now := time.Unix(base+3*3600+30, 0)
	if err := s.Maintain(now); err != nil {
		t.Fatal(err)
	}
	id := s.ids["cpu_pct"]
	count := func(step int64) int {
		var n int
		s.db.QueryRow(`SELECT count(*) FROM agg WHERE tier = ? AND metric = ?`, step, id).Scan(&n)
		return n
	}
	if got := count(60); got != 180 {
		t.Errorf("1m buckets: %d, want 180", got)
	}
	if got := count(300); got != 36 {
		t.Errorf("5m buckets: %d, want 36", got)
	}
	if got := count(3600); got != 3 {
		t.Errorf("1h buckets: %d, want 3", got)
	}
	// The hour with the spike: max 95 at the spike's time, avg slightly above 10.
	hour, err := aggs(s.db, 3600, id, base+3600, base+3601)
	if err != nil || len(hour) != 1 {
		t.Fatalf("spike hour: %v %v", hour, err)
	}
	a := hour[0]
	if a.N != 360 || a.Max != 95 || a.MaxAt != base+3600 || math.Abs(a.Avg-(359*10+95)/360.0) > 0.005 {
		t.Errorf("spike hour = %+v", a)
	}
	// One spike in 360 samples is not the hour's p95; the approximation reads
	// high (one 5-minute bucket of 12 had it) but stays under the max.
	if a.P95 >= 95 || a.P95 < 10 {
		t.Errorf("spike hour p95 = %v", a.P95)
	}
	// Running again changes nothing.
	if err := s.Maintain(now); err != nil {
		t.Fatal(err)
	}
	if got := count(60); got != 180 {
		t.Errorf("1m buckets after a second run: %d", got)
	}

	// A query over the last 2 hours at 120 points comes from the 1m tier, one bucket per point.
	res, err := s.Query("cpu_pct", time.Unix(base+3600, 0), time.Unix(base+3*3600, 0), 120)
	if err != nil {
		t.Fatal(err)
	}
	if res.Tier != "1m" || res.Step != 60 || len(res.Points) != 120 {
		t.Errorf("2h query: tier %s step %d points %d", res.Tier, res.Step, len(res.Points))
	}
	if res.Summary.Max != 95 || res.Summary.MaxAt.Unix() != base+3600 {
		t.Errorf("2h summary %+v", res.Summary)
	}
	// 30 points over 3 hours: 1m data regrouped into 6-minute points.
	res, err = s.Query("cpu_pct", time.Unix(base, 0), time.Unix(base+3*3600, 0), 30)
	if err != nil {
		t.Fatal(err)
	}
	if res.Tier != "1m" || res.Step != 360 || len(res.Points) != 30 {
		t.Errorf("30 points: tier %s step %d points %d", res.Tier, res.Step, len(res.Points))
	}
	// The last 10 minutes come from raw, with the exact p95.
	res, err = s.Query("cpu_pct", time.Unix(base+3*3600-600, 0), time.Unix(base+3*3600, 0), 120)
	if err != nil {
		t.Fatal(err)
	}
	if res.Tier != "10s" || len(res.Points) != 60 || res.Summary.P95 != 10 {
		t.Errorf("10 minutes: tier %s points %d summary %+v", res.Tier, len(res.Points), res.Summary)
	}
	if _, err := s.Query("nope", time.Unix(base, 0), time.Unix(base+60, 0), 10); err == nil {
		t.Error("an unknown metric answered")
	}

	// Peaks find the spike, and the next one is not its neighbour.
	pk, err := s.Peaks("cpu_*", time.Unix(base, 0), time.Unix(base+3*3600, 0), 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(pk) != 1 || pk[0].Peaks[0].Value != 95 || pk[0].Peaks[0].At.Unix() != base+3600 {
		t.Fatalf("peaks %+v", pk)
	}
	if len(pk[0].Peaks) != 3 || pk[0].Peaks[1].Value != 10 {
		t.Errorf("further peaks %+v", pk[0].Peaks)
	}
}

func TestRetentionAndTopPeaks(t *testing.T) {
	s := openTemp(t)
	base := int64(1_800_000_000)
	// cpu_pct with a peak at base+30; memory_pct flat.
	if err := s.Write(base+20, map[string]float64{"cpu_pct": 5, "memory_pct": 40}, []collect.Proc{{PID: 1, Comm: "a", CPUPct: 1}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Write(base+30, map[string]float64{"cpu_pct": 99, "memory_pct": 40}, []collect.Proc{{PID: 2, Comm: "hog", CPUPct: 90}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Write(base+40, map[string]float64{"cpu_pct": 6, "memory_pct": 40}, []collect.Proc{{PID: 1, Comm: "a", CPUPct: 1}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Maintain(time.Unix(base+120, 0)); err != nil {
		t.Fatal(err)
	}
	top, err := s.Top(time.Unix(base+31, 0))
	if err != nil || top.At.Unix() != base+30 || top.ByCPU[0].Comm != "hog" {
		t.Fatalf("top near the peak: %+v %v", top, err)
	}
	// Three days later: raw is gone, the 1m bucket stays, and so does the
	// process sample at the minute's cpu peak (base+30) and memory peak
	// (the first sample of a flat minute, base+20), but not base+40.
	later := time.Unix(base+3*86400, 0)
	if err := s.Maintain(later); err != nil {
		t.Fatal(err)
	}
	var raw, buckets, tops int
	s.db.QueryRow(`SELECT count(*) FROM raw`).Scan(&raw)
	s.db.QueryRow(`SELECT count(*) FROM agg WHERE tier = 60`).Scan(&buckets)
	s.db.QueryRow(`SELECT count(DISTINCT t) FROM top`).Scan(&tops)
	if raw != 0 || buckets != 2 || tops != 2 {
		t.Fatalf("after 3 days: raw %d, 1m buckets %d, top samples %d", raw, buckets, tops)
	}
	// Fifteen days: the peak samples are gone too, and the 1m bucket.
	if err := s.Maintain(time.Unix(base+15*86400, 0)); err != nil {
		t.Fatal(err)
	}
	s.db.QueryRow(`SELECT count(*) FROM agg WHERE tier = 60`).Scan(&buckets)
	s.db.QueryRow(`SELECT count(*) FROM top`).Scan(&tops)
	if buckets != 0 || tops != 0 {
		t.Fatalf("after 15 days: 1m buckets %d, top rows %d", buckets, tops)
	}
	var fives int
	s.db.QueryRow(`SELECT count(*) FROM agg WHERE tier = 300`).Scan(&fives)
	if fives != 2 {
		t.Fatalf("5m buckets kept: %d", fives)
	}
}

func TestSizeCapThinsRawFirst(t *testing.T) {
	s := openTemp(t)
	base := int64(1_800_000_000)
	names := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	// 24 hours of raw for 8 metrics.
	bulk(t, s, names, base, base+86400, 10, func(i int, ts int64) float64 { return float64(i) + float64(ts%97) })
	now := time.Unix(base+86400, 0)
	s.MaxBytes = 0
	if err := s.Maintain(now); err != nil {
		t.Fatal(err)
	}
	before, _ := s.LiveBytes()
	oldBuckets := 0
	s.db.QueryRow(`SELECT count(*) FROM agg WHERE tier = 60`).Scan(&oldBuckets)
	s.MaxBytes = before * 6 / 10
	cuts, err := s.EnforceCap(now)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := s.LiveBytes()
	oldest, _ := s.oldest(0)
	var buckets int
	s.db.QueryRow(`SELECT count(*) FROM agg WHERE tier = 60`).Scan(&buckets)
	t.Logf("live %d -> %d bytes (cap %d), %d cuts, raw now from %s", before, after, s.MaxBytes, cuts, time.Unix(oldest, 0).Sub(time.Unix(base, 0)))
	if cuts == 0 || after > s.MaxBytes {
		t.Fatalf("not under the cap: %d > %d after %d cuts", after, s.MaxBytes, cuts)
	}
	if oldest <= base || oldest > now.Add(-Tiers[0].Floor).Unix() {
		t.Fatalf("raw cut to %d, outside (base, floor]", oldest)
	}
	if buckets != oldBuckets {
		t.Fatalf("the 1m tier was thinned (%d -> %d) while raw had room above its floor", oldBuckets, buckets)
	}

	// A cap below what the floors allow: raw goes to its floor and stops
	// there; the 1m tier holds only a day, under its 2-day floor, so it stays.
	s.MaxBytes = 1
	if _, err := s.EnforceCap(now); err != nil {
		t.Fatal(err)
	}
	oldest, _ = s.oldest(0)
	if oldest < now.Add(-Tiers[0].Floor).Unix() {
		t.Fatalf("raw not at its floor: %s", now.Sub(time.Unix(oldest, 0)))
	}
	s.db.QueryRow(`SELECT count(*) FROM agg WHERE tier = 60`).Scan(&buckets)
	if buckets != oldBuckets {
		t.Fatalf("1m thinned below its floor: %d -> %d", oldBuckets, buckets)
	}
}

func TestReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.db")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Write(1_800_000_000, map[string]float64{"load1": 1.5}, nil, nil); err != nil {
		t.Fatal(err)
	}
	r, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	at, vals, err := r.Latest()
	if err != nil || at.Unix() != 1_800_000_000 || vals["load1"] != 1.5 {
		t.Fatalf("latest %v %v %v", at, vals, err)
	}
	if err := r.Write(1, nil, nil, nil); err == nil {
		t.Fatal("a read-only store wrote")
	}
	r.Close()
	w.Close()
	// After the writer's clean close the -shm is gone; reading still works.
	r, err = OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	if _, err := OpenReadOnly(filepath.Join(t.TempDir(), "missing.db")); err == nil {
		t.Fatal("opened a missing file")
	}
}
