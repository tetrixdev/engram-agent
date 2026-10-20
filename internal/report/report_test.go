package report

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/tetrixdev/engram-agent/internal/collect"
	"github.com/tetrixdev/engram-agent/internal/identity"
	"github.com/tetrixdev/engram-agent/internal/store"
)

// fakeEngram is an Engram stand-in: it checks what the protocol says it
// checks and answers what the test tells it to.
type fakeEngram struct {
	t       *testing.T
	mu      sync.Mutex
	pub     ed25519.PublicKey
	agentID string
	reports []Report
	keys    [][]string // event keys per request, accepted or not
	status  []int      // answers to give, in order; then 200
	code    string
}

func (f *fakeEngram) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	switch r.URL.Path {
	case "/agent/v1/enrol":
		var req EnrolRequest
		_ = json.Unmarshal(body, &req)
		if req.Code != "ABCD-EFGH-JKLM" {
			w.WriteHeader(403)
			w.Write([]byte(`{"code":"bad_code","error":"no such code"}`))
			return
		}
		raw, _ := base64.StdEncoding.DecodeString(req.PublicKey)
		f.pub = ed25519.PublicKey(raw)
		f.agentID = "3f2b8c1e-5a4d-4e6f-9b7a-1c2d3e4f5a6b"
		json.NewEncoder(w).Encode(EnrolResponse{AgentID: f.agentID, Fingerprint: identity.Fingerprint(f.pub), ReportEveryS: 60})
	case "/agent/v1/report":
		if len(body) > MaxBody {
			w.WriteHeader(413)
			return
		}
		ts, _ := strconv.ParseInt(r.Header.Get("X-Engram-Time"), 10, 64)
		sig, _ := base64.StdEncoding.DecodeString(r.Header.Get("X-Engram-Signature"))
		sum := sha256.Sum256(body)
		signed := "engram-agent-v1\n" + r.Header.Get("X-Engram-Agent") + "\n" + strconv.FormatInt(ts, 10) + "\n" + hex.EncodeToString(sum[:])
		if r.Header.Get("X-Engram-Agent") != f.agentID || !ed25519.Verify(f.pub, []byte(signed), sig) {
			w.WriteHeader(401)
			w.Write([]byte(`{"code":"bad_signature","error":"signature does not verify"}`))
			return
		}
		if d := time.Since(time.Unix(ts, 0)); d > 300*time.Second || d < -300*time.Second {
			w.WriteHeader(401)
			w.Write([]byte(`{"code":"clock","error":"time"}`))
			return
		}
		var rep Report
		if err := json.Unmarshal(body, &rep); err != nil {
			f.t.Errorf("report is not JSON: %v", err)
		}
		var ks []string
		for _, e := range rep.Events {
			ks = append(ks, e.Key)
		}
		f.keys = append(f.keys, ks)
		if len(f.status) > 0 {
			st := f.status[0]
			f.status = f.status[1:]
			w.Header().Set("Date", time.Now().Add(-10*time.Minute).UTC().Format(http.TimeFormat))
			w.WriteHeader(st)
			w.Write([]byte(`{"code":"` + f.code + `","error":"refused for the test"}`))
			return
		}
		f.reports = append(f.reports, rep)
		json.NewEncoder(w).Encode(Answer{OK: true, Accepted: len(rep.Events), ReportEveryS: 60})
	default:
		w.WriteHeader(404)
	}
}

type rig struct {
	f   *fakeEngram
	srv *httptest.Server
	r   *Reporter
	ob  *Outbox
	log *bytes.Buffer
	dir string
}

func newRig(t *testing.T) *rig {
	t.Helper()
	f := &fakeEngram{t: t}
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	ob, err := OpenOutbox(s.DB())
	if err != nil {
		t.Fatal(err)
	}
	// Enrol for real against the fake.
	key, err := identity.LoadOrCreateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	cl := NewClient("0.2.0")
	res, err := cl.Enrol(context.Background(), srv.URL, EnrolRequest{Code: "ABCD-EFGH-JKLM", PublicKey: PublicKeyB64(key), Hostname: "web01"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Fingerprint != identity.Fingerprint(key.Public().(ed25519.PublicKey)) {
		t.Fatalf("fingerprint %s", res.Fingerprint)
	}
	if err := identity.Save(dir, &identity.Identity{URL: srv.URL, AgentID: res.AgentID, Fingerprint: res.Fingerprint}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	meta := map[string]string{}
	var mm sync.Mutex
	r := &Reporter{Client: cl, StateDir: dir, Outbox: ob, Log: log.New(&buf, "", 0),
		Health: func(at time.Time) *Health {
			return BuildHealth([]collect.Sample{{T: at.Add(-5 * time.Second), Values: map[string]float64{"cpu_pct": 12, "memory_pct": 40, "disk_pct:/": 63, "load1": 0.5}}}, at, time.Minute)
		},
		SetMeta: func(k, v string) { mm.Lock(); meta[k] = v; mm.Unlock() },
	}
	r.init()
	if r.loadIdentity() == nil {
		t.Fatal("identity not loaded")
	}
	return &rig{f: f, srv: srv, r: r, ob: ob, log: &buf, dir: dir}
}

func (g *rig) add(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := g.ob.Add("alert.raised", "memory_pct", time.Now(), map[string]any{"rule": "memory_pct", "i": i}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEnrolRefusal(t *testing.T) {
	f := &fakeEngram{t: t}
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	defer srv.Close()
	_, err := NewClient("0.2.0").Enrol(context.Background(), srv.URL, EnrolRequest{Code: "WRONG"})
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("not accepted")) {
		t.Fatalf("%v", err)
	}
}

func TestReportSignedWithHealthAndEvents(t *testing.T) {
	g := newRig(t)
	g.add(t, 3)
	next := g.r.cycle(context.Background(), true)
	if len(g.f.reports) != 1 {
		t.Fatalf("reports %d; log %s", len(g.f.reports), g.log)
	}
	rep := g.f.reports[0]
	if rep.Health == nil || rep.Health.CPUPct.Avg != 12 || len(rep.Health.Disk) != 1 || rep.Health.Disk[0].Mount != "/" || len(rep.Events) != 3 {
		t.Fatalf("report %+v", rep)
	}
	if g.ob.Count() != 0 || g.r.state != StateOK {
		t.Fatalf("outbox %d state %s", g.ob.Count(), g.r.state)
	}
	if d := time.Until(next); d < 50*time.Second || d > 61*time.Second {
		t.Fatalf("next in %s", d)
	}
	// An events-only report carries neither host nor health.
	g.add(t, 1)
	g.r.cycle(context.Background(), false)
	if r := g.f.reports[1]; r.Health != nil || r.Host != nil || len(r.Events) != 1 {
		t.Fatalf("events-only %+v", r)
	}
}

func TestResendWithSameKeys(t *testing.T) {
	g := newRig(t)
	g.add(t, 2)
	g.f.status = []int{503}
	next := g.r.cycle(context.Background(), true)
	if g.ob.Count() != 2 || g.r.state != StateRetrying || time.Until(next) > 11*time.Second {
		t.Fatalf("after 503: outbox %d state %s next %s", g.ob.Count(), g.r.state, time.Until(next))
	}
	// A network error backs off further.
	url := g.r.id.URL
	g.r.id.URL = "http://127.0.0.1:1"
	next = g.r.cycle(context.Background(), true)
	if d := time.Until(next); d < 15*time.Second || d > 21*time.Second {
		t.Fatalf("second backoff %s", d)
	}
	g.r.id.URL = url
	g.r.cycle(context.Background(), true)
	if g.ob.Count() != 0 || len(g.f.keys) != 2 || g.f.keys[0][0] != g.f.keys[1][0] || g.f.keys[0][1] != g.f.keys[1][1] {
		t.Fatalf("keys across the resend: %v", g.f.keys)
	}
	if g.r.backoff != 0 {
		t.Fatal("backoff not reset")
	}
}

func TestQueueLongerThanOneReport(t *testing.T) {
	g := newRig(t)
	g.add(t, 45)
	g.r.cycle(context.Background(), true)
	if len(g.f.reports) != 3 || len(g.f.reports[0].Events) != 20 || len(g.f.reports[2].Events) != 5 || g.ob.Count() != 0 {
		t.Fatalf("reports %d, outbox %d", len(g.f.reports), g.ob.Count())
	}
	if g.f.reports[1].Health != nil {
		t.Fatal("the follow-up report repeated the health")
	}
}

func TestRemovedAndRefused(t *testing.T) {
	g := newRig(t)
	g.add(t, 1)
	g.f.status, g.f.code = []int{410}, "removed"
	next := g.r.cycle(context.Background(), true)
	if g.r.state != StateRemoved || time.Until(next) < 59*time.Minute || g.ob.Count() != 1 {
		t.Fatalf("410: state %s next %s", g.r.state, time.Until(next))
	}
	g.f.status, g.f.code = []int{401}, "clock"
	g.r.cycle(context.Background(), true)
	if g.r.state != StateClock || !bytes.Contains(g.log.Bytes(), []byte("clock is off by about 10m")) {
		t.Fatalf("clock: state %s log %s", g.r.state, g.log)
	}
	g.f.status, g.f.code = []int{401}, "unknown_agent"
	next = g.r.cycle(context.Background(), true)
	if g.r.state != StateUnauthorized || time.Until(next) < 59*time.Minute {
		t.Fatalf("401: %s", g.r.state)
	}
	// A key Engram does not know is refused by the fake itself.
	other, _ := identity.LoadOrCreateKey(t.TempDir())
	g.r.key = other
	g.r.cycle(context.Background(), true)
	if g.r.state != StateUnauthorized || !bytes.Contains(g.log.Bytes(), []byte("bad_signature")) {
		t.Fatalf("bad signature: %s %s", g.r.state, g.log)
	}
}

func TestTooLargeHalves(t *testing.T) {
	g := newRig(t)
	big := make([]byte, 60<<10)
	for i := range big {
		big[i] = 'a'
	}
	for i := 0; i < 6; i++ {
		if err := g.ob.Add("server.observed", "host", time.Now(), map[string]string{"pad": string(big)}); err != nil {
			t.Fatal(err)
		}
	}
	g.r.cycle(context.Background(), true)
	if g.ob.Count() != 0 {
		t.Fatalf("outbox %d; log %s", g.ob.Count(), g.log)
	}
	for _, r := range g.f.reports {
		b, _ := json.Marshal(r)
		if len(b) > MaxBody {
			t.Fatalf("a report of %d bytes", len(b))
		}
	}
	if err := g.ob.Add("x", "y", time.Now(), map[string]string{"pad": string(make([]byte, 70<<10))}); err == nil {
		t.Fatal("a state over 64 KB was queued")
	}
}

func TestOutboxBounded(t *testing.T) {
	g := newRig(t)
	g.add(t, MaxQueued+5)
	if n := g.ob.Count(); n != MaxQueued {
		t.Fatalf("outbox holds %d", n)
	}
}

func TestRunKickSendsAtOnce(t *testing.T) {
	g := newRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go g.r.Run(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for {
		g.f.mu.Lock()
		n := len(g.f.reports)
		g.f.mu.Unlock()
		if n >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no first report")
		}
		time.Sleep(20 * time.Millisecond)
	}
	g.add(t, 1)
	g.r.Kick()
	for {
		g.f.mu.Lock()
		n := len(g.f.reports)
		var evs int
		if n >= 2 {
			evs = len(g.f.reports[1].Events)
		}
		g.f.mu.Unlock()
		if n >= 2 {
			if evs != 1 {
				t.Fatalf("kicked report carried %d events", evs)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("a kick did not send")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
