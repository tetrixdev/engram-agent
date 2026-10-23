// Package report sends the agent's reports to Engram: signed POSTs of host
// facts, the last minute's health and the events waiting in the outbox.
package report

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Event is one event as the wire protocol carries it.
type Event struct {
	Type       string          `json:"type"`
	Ref        string          `json:"ref"`
	OccurredAt string          `json:"occurred_at"`
	Key        string          `json:"key"`
	State      json.RawMessage `json:"state"`
}

// MaxStateBytes is the most one event's state may hold (the protocol's 64 KB).
const MaxStateBytes = 64 << 10

// MaxQueued bounds the outbox: past it the oldest events are dropped, so an
// agent that cannot reach Engram for a month does not grow without bound.
const MaxQueued = 1000

// Outbox keeps events on disk until Engram has acknowledged them, so a
// restart or an outage loses none and a resend carries the same key.
type Outbox struct{ db *sql.DB }

// OpenOutbox creates the outbox table in the agent's database.
func OpenOutbox(db *sql.DB) (*Outbox, error) {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS outbox (seq INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT NOT NULL UNIQUE,
		type TEXT NOT NULL, ref TEXT NOT NULL, occurred_at TEXT NOT NULL, state TEXT NOT NULL, tries INTEGER NOT NULL DEFAULT 0)`)
	return &Outbox{db}, err
}

// NewKey is a fresh idempotency key: 16 random bytes, hex.
func NewKey() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Add queues an event with a new key.
func (o *Outbox) Add(typ, ref string, at time.Time, state any) error {
	return o.AddKeyed(typ, ref, NewKey(), at, state)
}

// AddKeyed queues an event with a key of the caller's: one whose key is
// already queued is not queued twice.
func (o *Outbox) AddKeyed(typ, ref, key string, at time.Time, state any) error {
	b, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if len(b) > MaxStateBytes {
		return fmt.Errorf("%s %s: state is %d bytes, over the %d the protocol allows", typ, ref, len(b), MaxStateBytes)
	}
	if key == "" || len(key) > 150 {
		return fmt.Errorf("%s %s: the key must be 1 to 150 characters", typ, ref)
	}
	if _, err := o.db.Exec(`INSERT OR IGNORE INTO outbox (key, type, ref, occurred_at, state) VALUES (?, ?, ?, ?, ?)`,
		key, typ, ref, at.UTC().Format(time.RFC3339), string(b)); err != nil {
		return err
	}
	_, err = o.db.Exec(`DELETE FROM outbox WHERE seq <= (SELECT max(seq) FROM outbox) - ?`, MaxQueued)
	return err
}

// Pending is the oldest n events.
func (o *Outbox) Pending(n int) ([]Event, error) {
	rows, err := o.db.Query(`SELECT key, type, ref, occurred_at, state FROM outbox ORDER BY seq LIMIT ?`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		var st string
		if err := rows.Scan(&e.Key, &e.Type, &e.Ref, &e.OccurredAt, &st); err != nil {
			return nil, err
		}
		e.State = json.RawMessage(st)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Ack removes events Engram accepted.
func (o *Outbox) Ack(events []Event) error {
	tx, err := o.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, e := range events {
		if _, err := tx.Exec(`DELETE FROM outbox WHERE key = ?`, e.Key); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Count is how many events wait.
func (o *Outbox) Count() int {
	var n int
	_ = o.db.QueryRow(`SELECT count(*) FROM outbox`).Scan(&n)
	return n
}

// Clear drops every queued event (a new enrolment: they were for the old one).
func (o *Outbox) Clear() error {
	_, err := o.db.Exec(`DELETE FROM outbox`)
	return err
}
