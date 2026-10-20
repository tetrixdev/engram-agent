package report

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/tetrixdev/engram-agent/internal/identity"
	"github.com/tetrixdev/engram-agent/internal/inventory"
)

// States the reporter is in, as `status` shows them.
const (
	StateNotEnrolled  = "not_enrolled"
	StateOK           = "ok"
	StateRetrying     = "retrying"     // a network error or a refusal that may pass; backing off
	StateRemoved      = "removed"      // 410: removed in Engram; trying once an hour
	StateUnauthorized = "unauthorized" // 401 bad_signature or unknown_agent; trying once an hour
	StateClock        = "clock"        // 401 clock: this server's clock is off
)

// Reporter is the report loop.
type Reporter struct {
	Client   *Client
	StateDir string
	Outbox   *Outbox
	Health   func(at time.Time) *Health
	Host     func() *inventory.Host
	Log      *log.Logger
	// SetMeta records the reporter's state for `status` (key, value).
	SetMeta func(key, value string)
	// OnIdentity is called when an identity is first seen or changes (a new
	// enrolment), before anything is sent for it.
	OnIdentity func(id *identity.Identity)
	// Every is the regular interval; Engram's report_every_s overrides it.
	Every time.Duration

	kick chan struct{}
	once sync.Once

	id        *identity.Identity
	key       ed25519.PrivateKey
	state     string
	backoff   time.Duration
	maxEvents int
}

func (r *Reporter) init() {
	r.once.Do(func() {
		r.kick = make(chan struct{}, 1)
		if r.Every <= 0 {
			r.Every = time.Minute
		}
		r.maxEvents = MaxEvents
	})
}

// Kick asks for a report now: an alert was raised or resolved.
func (r *Reporter) Kick() {
	r.init()
	select {
	case r.kick <- struct{}{}:
	default:
	}
}

func (r *Reporter) setState(s, detail string) {
	if s != r.state {
		r.state = s
		if r.SetMeta != nil {
			r.SetMeta("report.state", s)
		}
	}
	if r.SetMeta != nil && detail != "" {
		r.SetMeta("report.detail", detail)
	}
}

// loadIdentity reads identity.json and the key; nil while not enrolled.
func (r *Reporter) loadIdentity() *identity.Identity {
	id, err := identity.Load(r.StateDir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			r.Log.Printf("report: %v", err)
		}
		return nil
	}
	if r.id != nil && r.id.AgentID == id.AgentID && r.id.URL == id.URL {
		return r.id
	}
	key, err := identity.LoadKey(r.StateDir)
	if err != nil {
		r.Log.Printf("report: enrolled as %s but the key cannot be read: %v", id.AgentID, err)
		return nil
	}
	r.id, r.key = id, key
	if id.ReportEveryS > 0 {
		r.Every = clampEvery(id.ReportEveryS)
	}
	r.Log.Printf("report: enrolled with %s as %s (fingerprint %s); reporting every %s", id.URL, id.AgentID, id.Fingerprint, r.Every)
	r.state, r.backoff = "", 0
	if r.OnIdentity != nil {
		r.OnIdentity(id)
	}
	return r.id
}

func clampEvery(s int) time.Duration {
	d := time.Duration(s) * time.Second
	return time.Duration(math.Max(float64(15*time.Second), math.Min(float64(time.Hour), float64(d))))
}

// Run reports until ctx ends.
func (r *Reporter) Run(ctx context.Context) {
	r.init()
	next := time.Now() // the first report goes at once
	for {
		var wait <-chan time.Time
		d := time.Until(next)
		if d < 0 {
			d = 0
		}
		timer := time.NewTimer(d)
		wait = timer.C
		kicked := false
		select {
		case <-ctx.Done():
			timer.Stop()
			r.flush()
			return
		case <-wait:
		case <-r.kick:
			timer.Stop()
			kicked = true
		}
		id := r.loadIdentity()
		if id == nil {
			r.setState(StateNotEnrolled, "")
			next = time.Now().Add(time.Minute)
			continue
		}
		// A kick while backing off, removed or refused waits for the timer.
		if kicked && r.state != "" && r.state != StateOK {
			continue
		}
		next = r.cycle(ctx, !kicked)
	}
}

// flush sends what waits in the outbox once more on the way out (a
// stopping service), for at most five seconds.
func (r *Reporter) flush() {
	if r.id == nil || (r.state != StateOK && r.state != "") || r.Outbox.Count() == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r.cycle(ctx, false)
}

// cycle sends one report (and more while events wait) and says when to send next.
func (r *Reporter) cycle(ctx context.Context, regular bool) time.Time {
	full := regular
	for i := 0; i < 50; i++ {
		events, err := r.Outbox.Pending(r.maxEvents)
		if err != nil {
			r.Log.Printf("report: outbox: %v", err)
			return time.Now().Add(r.Every)
		}
		if !full && len(events) == 0 {
			return time.Now().Add(r.Every)
		}
		body, sent := r.body(full, events)
		ans, err := r.Client.Send(ctx, r.id, r.key, body)
		if err != nil {
			return r.failed(err, len(sent))
		}
		if err := r.Outbox.Ack(sent); err != nil {
			r.Log.Printf("report: outbox ack: %v", err)
		}
		if ans.ReportEveryS > 0 {
			r.Every = clampEvery(ans.ReportEveryS)
		}
		if r.state != StateOK && r.state != "" {
			r.Log.Printf("report: Engram accepts reports again")
		}
		r.setState(StateOK, "")
		r.backoff = 0
		r.maxEvents = MaxEvents
		if r.SetMeta != nil {
			r.SetMeta("report.last_ok", time.Now().UTC().Format(time.RFC3339))
		}
		if r.Outbox.Count() == 0 {
			break
		}
		full = false // the rest of the queue goes in events-only reports
	}
	return time.Now().Add(r.Every)
}

// body builds a report within MaxBody, carrying as many of events as fit.
func (r *Reporter) body(full bool, events []Event) ([]byte, []Event) {
	rep := Report{AgentVersion: r.Client.Version, Events: events}
	if full {
		if r.Host != nil {
			rep.Host = r.Host()
		}
		if r.Health != nil {
			rep.Health = r.Health(time.Now())
		}
	}
	for {
		b, _ := json.Marshal(rep)
		if len(b) <= MaxBody || len(rep.Events) <= 1 {
			return b, rep.Events
		}
		rep.Events = rep.Events[:len(rep.Events)/2]
	}
}

// failed decides what a failed send means and when to try again.
func (r *Reporter) failed(err error, nEvents int) time.Time {
	var ae *APIError
	if !errors.As(err, &ae) {
		return r.retry("report: cannot reach Engram: " + err.Error())
	}
	switch {
	case ae.Status == http.StatusGone:
		if r.state != StateRemoved {
			r.Log.Printf("report: this server was removed in Engram (%s); not sending any more, collecting on, trying again once an hour", ae.Message)
		}
		r.setState(StateRemoved, ae.Message)
		return time.Now().Add(time.Hour)
	case ae.Status == http.StatusUnauthorized && ae.Code == "clock":
		msg := "report: Engram refused the report's time: this server's clock is off"
		if !ae.Date.IsZero() {
			msg += " by about " + time.Since(ae.Date).Round(time.Second).String() + " (Engram's clock says " + ae.Date.UTC().Format(time.RFC3339) + ")"
		}
		msg += "; fix the time (timedatectl status, NTP)"
		r.Log.Print(msg)
		r.setState(StateClock, msg)
		return time.Now().Add(r.grow())
	case ae.Status == http.StatusUnauthorized:
		r.Log.Printf("report: Engram does not accept this agent (%s); enrol again if it was removed; trying again once an hour", ae.Error())
		r.setState(StateUnauthorized, ae.Error())
		return time.Now().Add(time.Hour)
	case ae.Status == http.StatusRequestEntityTooLarge:
		if nEvents <= 1 {
			// One event Engram will never take: drop it rather than block the queue.
			if evs, _ := r.Outbox.Pending(1); len(evs) == 1 {
				r.Log.Printf("report: Engram refused event %s %s as too large; dropped", evs[0].Type, evs[0].Ref)
				_ = r.Outbox.Ack(evs)
			}
		} else {
			r.maxEvents = max(1, nEvents/2)
		}
		return time.Now().Add(time.Second)
	case ae.Status == http.StatusTooManyRequests:
		d := ae.Retry
		if d <= 0 {
			d = time.Minute
		}
		r.setState(StateRetrying, ae.Error())
		return time.Now().Add(d)
	}
	return r.retry("report: " + ae.Error())
}

func (r *Reporter) retry(msg string) time.Time {
	d := r.grow()
	r.Log.Printf("%s; next try in %s", msg, d)
	r.setState(StateRetrying, msg)
	return time.Now().Add(d)
}

// grow doubles the backoff: 10 s, 20 s, ... up to 10 minutes.
func (r *Reporter) grow() time.Duration {
	if r.backoff == 0 {
		r.backoff = 10 * time.Second
	} else {
		r.backoff *= 2
	}
	if r.backoff > 10*time.Minute {
		r.backoff = 10 * time.Minute
	}
	return r.backoff
}
