package store

import (
	"math"
	"sort"
)

// Point is one raw sample.
type Point struct {
	T int64
	V float64
}

// Agg is one downsampled bucket: how many raw samples it covers, their mean,
// their 95th percentile, their maximum and when the maximum was seen.
type Agg struct {
	T     int64   `json:"t"`
	N     int64   `json:"n"`
	Avg   float64 `json:"avg"`
	P95   float64 `json:"p95"`
	Max   float64 `json:"max"`
	MaxAt int64   `json:"max_at"`
}

// Percentile is the q-th quantile (0..1) of values by linear interpolation
// between the two nearest ranks (Hyndman and Fan type 7, what numpy and
// spreadsheets call PERCENTILE.INC). values need not be sorted; it is not
// modified.
func Percentile(values []float64, q float64) float64 {
	if len(values) == 0 {
		return 0
	}
	s := append([]float64(nil), values...)
	sort.Float64s(s)
	h := q * float64(len(s)-1)
	lo := int(math.Floor(h))
	hi := int(math.Ceil(h))
	return s[lo] + (h-float64(lo))*(s[hi]-s[lo])
}

// FromRaw aggregates raw points exactly: the p95 is that of the points themselves.
func FromRaw(t int64, pts []Point) Agg {
	a := Agg{T: t}
	if len(pts) == 0 {
		return a
	}
	vals := make([]float64, len(pts))
	sum := 0.0
	a.Max = math.Inf(-1)
	for i, p := range pts {
		vals[i] = p.V
		sum += p.V
		if p.V > a.Max {
			a.Max, a.MaxAt = p.V, p.T
		}
	}
	a.N = int64(len(pts))
	a.Avg = sum / float64(len(pts))
	a.P95 = Percentile(vals, 0.95)
	return a
}

// FromAggs aggregates finer buckets into a coarser one. The mean is exact
// (weighted by each bucket's sample count) and so are max and max_at. The raw
// points are gone by then, so the p95 is APPROXIMATED: it is the 95th
// percentile of the finer buckets' p95 values, each weighted by its sample
// count (WeightedPercentile), never above the coarse maximum. It is exact when
// the load is steady and reads high when one finer bucket held a burst; the
// README says so.
func FromAggs(t int64, kids []Agg) Agg {
	a := Agg{T: t}
	if len(kids) == 0 {
		return a
	}
	sum := 0.0
	a.Max = math.Inf(-1)
	vals := make([]float64, 0, len(kids))
	weights := make([]float64, 0, len(kids))
	for _, k := range kids {
		if k.N <= 0 {
			continue
		}
		a.N += k.N
		sum += k.Avg * float64(k.N)
		if k.Max > a.Max || (k.Max == a.Max && k.MaxAt < a.MaxAt) {
			a.Max, a.MaxAt = k.Max, k.MaxAt
		}
		vals = append(vals, k.P95)
		weights = append(weights, float64(k.N))
	}
	if a.N == 0 {
		return Agg{T: t}
	}
	a.Avg = sum / float64(a.N)
	a.P95 = math.Min(WeightedPercentile(vals, weights, 0.95), a.Max)
	return a
}

// WeightedPercentile is the q-th quantile of values with weights: each value
// sits at the middle of its share of the cumulative weight, and the quantile
// interpolates linearly between those positions (below the first, the
// smallest value; above the last, the largest). With equal weights and many
// values it tends to Percentile.
func WeightedPercentile(values, weights []float64, q float64) float64 {
	n := len(values)
	if n == 0 {
		return 0
	}
	idx := make([]int, n)
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(a, b int) bool { return values[idx[a]] < values[idx[b]] })
	total := 0.0
	for _, w := range weights {
		total += w
	}
	if total <= 0 {
		return values[idx[n-1]]
	}
	cum := 0.0
	prevPos, prevVal := -1.0, 0.0
	for k, i := range idx {
		pos := (cum + weights[i]/2) / total
		cum += weights[i]
		if q <= pos {
			if k == 0 {
				return values[i]
			}
			f := (q - prevPos) / (pos - prevPos)
			return prevVal + f*(values[i]-prevVal)
		}
		prevPos, prevVal = pos, values[i]
	}
	return values[idx[n-1]]
}
