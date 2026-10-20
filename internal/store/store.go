// Package store keeps the agent's history in one SQLite file: raw samples,
// three downsampled tiers with avg, p95 and max per bucket, and the top
// processes. The service writes it; every read command opens it read-only.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/tetrixdev/engram-agent/internal/collect"
	_ "modernc.org/sqlite" // pure Go SQLite: the binary stays static (CGO_ENABLED=0)
)

// Tier is one resolution of history.
type Tier struct {
	Name string
	Step int64         // seconds per bucket
	Keep time.Duration // how long its buckets are kept
	// Floor is how far the size cap may cut this tier back: never below it.
	Floor time.Duration
}

const day = 24 * time.Hour

// Tiers, finest first. Raw (10 s) is its own table; the others are buckets.
var Tiers = []Tier{
	{Name: "10s", Step: 10, Keep: 48 * time.Hour, Floor: 6 * time.Hour},
	{Name: "1m", Step: 60, Keep: 14 * day, Floor: 2 * day},
	{Name: "5m", Step: 300, Keep: 90 * day, Floor: 14 * day},
	{Name: "1h", Step: 3600, Keep: 396 * day, Floor: 30 * day}, // 13 months
}

// Top-process samples: every one for 48 h, the one at each minute's peak for 14 days.
const (
	TopKeep     = 48 * time.Hour
	TopPeakKeep = 14 * day
)

// DefaultMaxBytes is the default size cap: 500 MB.
const DefaultMaxBytes = 500 << 20

// Store is an open history database.
type Store struct {
	db       *sql.DB
	readOnly bool
	MaxBytes int64

	mu   sync.Mutex
	ids  map[string]int64
	seen map[int64]int64 // metric id -> last sample time, flushed to metrics.last_t

	lastRetain int64
}

const schema = `
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS metrics (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, last_t INTEGER NOT NULL DEFAULT 0);
-- Values are stored as integers in hundredths (v = round(value * 100)):
-- SQLite keeps a small integer in 1 to 4 bytes and every REAL in 8, which
-- halves the file. max_off is max_at - t, small for the same reason.
CREATE TABLE IF NOT EXISTS raw (metric INTEGER NOT NULL, t INTEGER NOT NULL, v INTEGER NOT NULL, PRIMARY KEY (metric, t)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS agg (tier INTEGER NOT NULL, metric INTEGER NOT NULL, t INTEGER NOT NULL, n INTEGER NOT NULL,
  avg INTEGER NOT NULL, p95 INTEGER NOT NULL, max INTEGER NOT NULL, max_off INTEGER NOT NULL, PRIMARY KEY (tier, metric, t)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS top (t INTEGER NOT NULL, by TEXT NOT NULL, rank INTEGER NOT NULL, pid INTEGER NOT NULL,
  comm TEXT NOT NULL, uid INTEGER NOT NULL, cpu_pct REAL NOT NULL, rss INTEGER NOT NULL, keep INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (t, by, rank)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS rollup (tier INTEGER PRIMARY KEY, done_until INTEGER NOT NULL);
`

// Open opens (and creates) the database for writing: the service.
func Open(path string) (*Store, error) {
	dsn := "file:" + escapePath(path) + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=auto_vacuum(INCREMENTAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create schema in %s: %w", path, err)
	}
	s := &Store{db: db, MaxBytes: DefaultMaxBytes, ids: map[string]int64{}, seen: map[int64]int64{}}
	if err := s.loadIDs(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// OpenReadOnly opens an existing database for the read commands. It never
// creates or changes anything, so it works as any user who may read the file.
//
// A reader that may not write the directory cannot create the WAL's -shm
// file. While the service runs, the file exists and is shared read-only.
// When the service is stopped, SQLite has checkpointed and removed both
// -wal and -shm on its clean close, and nothing is writing: the file is then
// opened immutable, which needs neither.
func OpenReadOnly(path string) (*Store, error) {
	s, err := openRO(path, "?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil && strings.Contains(err.Error(), "readonly database") {
		s, err = openRO(path, "?mode=ro&immutable=1")
	}
	if err != nil {
		return nil, readErr(path, err)
	}
	return s, nil
}

func openRO(path, params string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+escapePath(path)+params)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, readOnly: true, ids: map[string]int64{}, seen: map[int64]int64{}}
	if err := s.loadIDs(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func readErr(path string, err error) error {
	msg := err.Error()
	if strings.Contains(msg, "unable to open") || strings.Contains(msg, "permission") || strings.Contains(msg, "no such table") {
		return fmt.Errorf("cannot read %s (%v): is engram-agent running, and are you in group engram-agent?", path, err)
	}
	return fmt.Errorf("read %s: %w", path, err)
}

func escapePath(p string) string {
	return (&url.URL{Path: p}).EscapedPath()
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// DB is the handle, for packages that keep their own tables in the same file.
func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) loadIDs() error {
	rows, err := s.db.Query(`SELECT id, name FROM metrics`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return err
		}
		s.ids[name] = id
	}
	return rows.Err()
}

// Meta reads a value from the meta table ("" when absent).
func (s *Store) Meta(key string) string {
	var v string
	_ = s.db.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	return v
}

// SetMeta writes a value to the meta table.
func (s *Store) SetMeta(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// Write stores one sample: its values at time t (seconds, aligned by the
// caller) and its top processes.
func (s *Store) Write(t int64, values map[string]float64, topCPU, topMem []collect.Proc) error {
	if s.readOnly {
		return errors.New("store is read-only")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	ins, err := tx.Prepare(`INSERT OR REPLACE INTO raw (metric, t, v) VALUES (?, ?, ?)`)
	if err != nil {
		return err
	}
	defer ins.Close()
	for name, v := range values {
		id, err := s.idTx(tx, name)
		if err != nil {
			return err
		}
		if _, err := ins.Exec(id, t, enc(v)); err != nil {
			return err
		}
		s.seen[id] = t
	}
	for by, list := range map[string][]collect.Proc{"cpu": topCPU, "mem": topMem} {
		for i, p := range list {
			if _, err := tx.Exec(`INSERT OR REPLACE INTO top (t, by, rank, pid, comm, uid, cpu_pct, rss) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				t, by, i+1, p.PID, p.Comm, p.UID, p.CPUPct, int64(p.RSS)); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func (s *Store) idTx(tx *sql.Tx, name string) (int64, error) {
	if id, ok := s.ids[name]; ok {
		return id, nil
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO metrics (name) VALUES (?)`, name); err != nil {
		return 0, err
	}
	var id int64
	if err := tx.QueryRow(`SELECT id FROM metrics WHERE name = ?`, name).Scan(&id); err != nil {
		return 0, err
	}
	s.ids[name] = id
	return id, nil
}

// flushSeen records the last sample time per metric, so the rollup and the
// read commands only visit metrics that have data in a window.
func (s *Store) flushSeen() error {
	s.mu.Lock()
	seen := s.seen
	s.seen = map[int64]int64{}
	s.mu.Unlock()
	if len(seen) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for id, t := range seen {
		if _, err := tx.Exec(`UPDATE metrics SET last_t = max(last_t, ?) WHERE id = ?`, t, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// metricsSince lists metric ids with a sample at or after t.
func (s *Store) metricsSince(t int64) ([]int64, error) {
	rows, err := s.db.Query(`SELECT id FROM metrics WHERE last_t >= ? ORDER BY id`, t)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// Maintain does what the service does once a minute: flush, roll up every
// complete bucket of every tier, mark top-process peaks, apply retention and
// the size cap.
func (s *Store) Maintain(now time.Time) error {
	if err := s.flushSeen(); err != nil {
		return err
	}
	for i := 1; i < len(Tiers); i++ {
		if err := s.rollup(i, now); err != nil {
			return fmt.Errorf("rollup %s: %w", Tiers[i].Name, err)
		}
	}
	// Retention every ten minutes is plenty: nothing is kept to the second.
	if now.Unix()/600 != s.lastRetain/600 {
		if err := s.retain(now); err != nil {
			return fmt.Errorf("retention: %w", err)
		}
		s.lastRetain = now.Unix()
	}
	if _, err := s.EnforceCap(now); err != nil {
		return fmt.Errorf("size cap: %w", err)
	}
	return nil
}

// enc and dec convert a value to and from its stored form, hundredths.
func enc(v float64) int64 { return int64(math.Round(v * 100)) }
func dec(i int64) float64 { return float64(i) / 100 }

func floorTo(t, step int64) int64 { return t - ((t%step)+step)%step }

// rollup fills tier i from tier i-1 for every bucket that is complete.
func (s *Store) rollup(i int, now time.Time) error {
	tier, src := Tiers[i], Tiers[i-1]
	end := floorTo(now.Unix(), tier.Step) // the bucket starting here is not complete
	var done int64
	err := s.db.QueryRow(`SELECT done_until FROM rollup WHERE tier = ?`, tier.Step).Scan(&done)
	if errors.Is(err, sql.ErrNoRows) {
		// First run: start from the oldest data the source tier still has.
		done = floorTo(now.Add(-src.Keep).Unix(), tier.Step)
		if oldest, ok := s.oldest(i - 1); ok && oldest > done {
			done = floorTo(oldest, tier.Step)
		}
	} else if err != nil {
		return err
	}
	// Never reach back past what the source tier keeps (an agent stopped for a week).
	if lo := floorTo(now.Add(-src.Keep).Unix(), tier.Step); done < lo {
		done = lo
	}
	if done >= end {
		return nil
	}
	ids, err := s.metricsSince(done)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	put, err := tx.Prepare(`INSERT OR REPLACE INTO agg (tier, metric, t, n, avg, p95, max, max_off) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer put.Close()
	var peaks []int64 // max_at of cpu_pct and memory_pct per minute, for the top table
	cpuID, memID := s.ids["cpu_pct"], s.ids["memory_pct"]
	for _, id := range ids {
		buckets, err := s.bucketsFrom(tx, i-1, id, done, end, tier.Step)
		if err != nil {
			return err
		}
		for _, a := range buckets {
			if _, err := put.Exec(tier.Step, id, a.T, a.N, enc(a.Avg), enc(a.P95), enc(a.Max), a.MaxAt-a.T); err != nil {
				return err
			}
			if i == 1 && (id == cpuID || id == memID) {
				peaks = append(peaks, a.MaxAt)
			}
		}
	}
	for _, t := range peaks {
		if _, err := tx.Exec(`UPDATE top SET keep = 1 WHERE t = ?`, t); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT INTO rollup (tier, done_until) VALUES (?, ?) ON CONFLICT (tier) DO UPDATE SET done_until = excluded.done_until`, tier.Step, end); err != nil {
		return err
	}
	return tx.Commit()
}

type querier interface {
	Query(string, ...any) (*sql.Rows, error)
}

// bucketsFrom reads tier src for one metric in [from, to) and aggregates it
// into buckets of step seconds counted from `from` (aligned for a rollup,
// whose from is on a bucket boundary; counted from the range's start for a
// query, so merging never adds a partial point).
func (s *Store) bucketsFrom(q querier, src int, id, from, to, step int64) ([]Agg, error) {
	if src == 0 {
		pts, err := rawPoints(q, id, from, to)
		if err != nil {
			return nil, err
		}
		var out []Agg
		for len(pts) > 0 {
			b := from + floorTo(pts[0].T-from, step)
			j := 0
			for j < len(pts) && from+floorTo(pts[j].T-from, step) == b {
				j++
			}
			out = append(out, FromRaw(b, pts[:j]))
			pts = pts[j:]
		}
		return out, nil
	}
	kids, err := aggs(q, Tiers[src].Step, id, from, to)
	if err != nil {
		return nil, err
	}
	var out []Agg
	for len(kids) > 0 {
		b := from + floorTo(kids[0].T-from, step)
		j := 0
		for j < len(kids) && from+floorTo(kids[j].T-from, step) == b {
			j++
		}
		out = append(out, FromAggs(b, kids[:j]))
		kids = kids[j:]
	}
	return out, nil
}

func rawPoints(q querier, id, from, to int64) ([]Point, error) {
	rows, err := q.Query(`SELECT t, v FROM raw WHERE metric = ? AND t >= ? AND t < ? ORDER BY t`, id, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Point
	for rows.Next() {
		var p Point
		var v int64
		if err := rows.Scan(&p.T, &v); err != nil {
			return nil, err
		}
		p.V = dec(v)
		out = append(out, p)
	}
	return out, rows.Err()
}

func aggs(q querier, step, id, from, to int64) ([]Agg, error) {
	rows, err := q.Query(`SELECT t, n, avg, p95, max, max_off FROM agg WHERE tier = ? AND metric = ? AND t >= ? AND t < ? ORDER BY t`, step, id, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Agg
	for rows.Next() {
		var a Agg
		var avg, p95, max, off int64
		if err := rows.Scan(&a.T, &a.N, &avg, &p95, &max, &off); err != nil {
			return nil, err
		}
		a.Avg, a.P95, a.Max, a.MaxAt = dec(avg), dec(p95), dec(max), a.T+off
		out = append(out, a)
	}
	return out, rows.Err()
}

// oldest is the oldest bucket time in tier i, over all metrics.
func (s *Store) oldest(i int) (int64, bool) {
	var t sql.NullInt64
	if i == 0 {
		_ = s.db.QueryRow(`SELECT min(t) FROM raw`).Scan(&t)
	} else {
		_ = s.db.QueryRow(`SELECT min(t) FROM agg WHERE tier = ?`, Tiers[i].Step).Scan(&t)
	}
	return t.Int64, t.Valid
}

func (s *Store) allMetricIDs() ([]int64, error) { return s.metricsSince(-1 << 62) }

// deleteBefore removes tier i's rows older than t, metric by metric (the
// primary key leads with the metric, so each delete is a range).
func (s *Store) deleteBefore(i int, t int64) error {
	ids, err := s.allMetricIDs()
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range ids {
		if i == 0 {
			_, err = tx.Exec(`DELETE FROM raw WHERE metric = ? AND t < ?`, id, t)
		} else {
			_, err = tx.Exec(`DELETE FROM agg WHERE tier = ? AND metric = ? AND t < ?`, Tiers[i].Step, id, t)
		}
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) retain(now time.Time) error {
	for i, tier := range Tiers {
		if err := s.deleteBefore(i, now.Add(-tier.Keep).Unix()); err != nil {
			return err
		}
	}
	if _, err := s.db.Exec(`DELETE FROM top WHERE keep = 0 AND t < ?`, now.Add(-TopKeep).Unix()); err != nil {
		return err
	}
	if _, err := s.db.Exec(`DELETE FROM top WHERE t < ?`, now.Add(-TopPeakKeep).Unix()); err != nil {
		return err
	}
	// Metrics that have had no data for longer than everything is kept (a
	// container removed a year ago) go too.
	_, err := s.db.Exec(`DELETE FROM metrics WHERE last_t > 0 AND last_t < ? AND id NOT IN (SELECT DISTINCT metric FROM agg WHERE tier = ?)`,
		now.Add(-Tiers[len(Tiers)-1].Keep).Unix(), Tiers[len(Tiers)-1].Step)
	if err == nil {
		s.mu.Lock()
		s.ids = map[string]int64{}
		s.mu.Unlock()
		err = s.loadIDs()
	}
	return err
}

// LiveBytes is how much of the file holds data (pages not on the free list).
func (s *Store) LiveBytes() (int64, error) {
	var pages, free, size int64
	if err := s.db.QueryRow(`PRAGMA page_count`).Scan(&pages); err != nil {
		return 0, err
	}
	if err := s.db.QueryRow(`PRAGMA freelist_count`).Scan(&free); err != nil {
		return 0, err
	}
	if err := s.db.QueryRow(`PRAGMA page_size`).Scan(&size); err != nil {
		return 0, err
	}
	return (pages - free) * size, nil
}

// EnforceCap thins history while the file holds more than MaxBytes. It cuts
// the oldest rows of the finest tier first, because every minute of those is
// also kept in a coarser tier: the cap costs resolution before it costs
// coverage. Each tier is cut back at most to its Floor, then the next tier
// is thinned. It returns how many cuts it made.
func (s *Store) EnforceCap(now time.Time) (int, error) {
	if s.MaxBytes <= 0 {
		return 0, nil
	}
	cuts := 0
	for i := range Tiers {
		for guard := 0; guard < 100; guard++ {
			live, err := s.LiveBytes()
			if err != nil {
				return cuts, err
			}
			if live <= s.MaxBytes {
				if cuts > 0 {
					_, err = s.db.Exec(`PRAGMA incremental_vacuum`)
				}
				return cuts, err
			}
			oldest, ok := s.oldest(i)
			floor := now.Add(-Tiers[i].Floor).Unix()
			if !ok || oldest >= floor {
				break // this tier is at its floor: thin the next one
			}
			// Cut a tenth of what lies between the oldest row and the floor,
			// and at least a twentieth of what the tier keeps above its floor,
			// so a few dozen cuts reach the floor.
			cut := oldest + max((floor-oldest)/10, int64((Tiers[i].Keep-Tiers[i].Floor)/time.Second)/20, Tiers[i].Step)
			if cut > floor {
				cut = floor
			}
			if err := s.deleteBefore(i, cut); err != nil {
				return cuts, err
			}
			if i == 0 {
				if _, err := s.db.Exec(`DELETE FROM top WHERE keep = 0 AND t < ?`, cut); err != nil {
					return cuts, err
				}
			}
			cuts++
		}
	}
	if cuts > 0 {
		_, err := s.db.Exec(`PRAGMA incremental_vacuum`)
		return cuts, err
	}
	return cuts, nil
}
