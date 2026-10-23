// Package state builds the observed-state sections the agent sends as
// state.observed events: the package list, the network, the listening ports
// judged by scope, and the five sections of the root snapshot, each with a
// sha256 so a section is sent only when it changed, and cut into parts that
// stay under Engram's per-event limit.
package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// MaxPartBytes is the most one part's state may take as JSON: under 48 KB,
// well inside Engram's 64 KB per event.
const MaxPartBytes = 48 << 10

// Names are the sections, in the order they are sent.
var Names = []string{"packages", "network", "ports", "firewall", "containers", "users", "ssh_keys", "tailscale", "snapshot"}

// Section is one section as it is compared and sent.
type Section struct {
	Name        string
	CollectedAt time.Time
	Items       []json.RawMessage
	Meta        json.RawMessage // a JSON object; {} when none
	Error       *string
}

// PartState is a state.observed event's state, with exactly the keys the
// Servers app declares.
type PartState struct {
	Section     string            `json:"section"`
	CollectedAt string            `json:"collected_at"`
	SHA256      string            `json:"sha256"`
	Part        int               `json:"part"`
	Parts       int               `json:"parts"`
	Items       []json.RawMessage `json:"items"`
	Meta        json.RawMessage   `json:"meta"`
	Error       *string           `json:"error"`
}

// Event is one state.observed event to queue.
type Event struct {
	Ref   string
	Key   string
	State PartState
}

func (s Section) meta() json.RawMessage {
	if len(bytes.TrimSpace(s.Meta)) == 0 || string(bytes.TrimSpace(s.Meta)) == "null" {
		return json.RawMessage("{}")
	}
	return s.Meta
}

func (s Section) items() []json.RawMessage {
	if s.Items == nil {
		return []json.RawMessage{}
	}
	return s.Items
}

// Canonical is JSON with object keys sorted, no insignificant whitespace,
// numbers as written and no HTML escaping.
func Canonical(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var g any
	if err := dec.Decode(&g); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(g); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// SHA256 is the hex sha256 of the canonical JSON of {items, meta, error}.
func (s Section) SHA256() string {
	b, err := Canonical(map[string]any{"items": s.items(), "meta": s.meta(), "error": s.Error})
	if err != nil {
		b = []byte(err.Error())
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Events cuts a section into its state.observed events. The package list
// always uses the ref state:packages:<i>; any other section is one event,
// ref state:<section>, unless it outgrows one part, when it is cut the same
// way. stamp makes the keys of this sending unique (see Key).
func (s Section) Events(stamp int64) []Event {
	sum := s.SHA256()
	at := s.CollectedAt.UTC().Format(time.RFC3339)
	items := s.items()
	meta := s.meta()
	base := func(part int, its []json.RawMessage) PartState {
		m := json.RawMessage("{}")
		if part == 1 {
			m = meta
		}
		return PartState{Section: s.Name, CollectedAt: at, SHA256: sum, Part: part, Items: its, Meta: m, Error: s.Error}
	}
	// Greedy: fill a part until the next item would take it over the limit.
	// 40 bytes are kept for the part and parts numbers, filled in after.
	var groups [][]json.RawMessage
	cur := []json.RawMessage{}
	empty, _ := json.Marshal(base(1, []json.RawMessage{}))
	size := len(empty) + 40
	for _, it := range items {
		if len(cur) > 0 && size+len(it)+1 > MaxPartBytes {
			groups = append(groups, cur)
			cur = []json.RawMessage{}
			e2, _ := json.Marshal(base(2, []json.RawMessage{}))
			size = len(e2) + 40
		}
		cur = append(cur, it)
		size += len(it) + 1
	}
	groups = append(groups, cur)
	chunked := s.Name == "packages" || len(groups) > 1
	out := make([]Event, 0, len(groups))
	for i, g := range groups {
		st := base(i+1, g)
		st.Parts = len(groups)
		ref := "state:" + s.Name
		if chunked {
			ref = fmt.Sprintf("state:%s:%d", s.Name, i+1)
		}
		out = append(out, Event{Ref: ref, Key: Key(s.Name, i+1, sum, stamp), State: st})
	}
	return out
}

// Key is an event's idempotency key: state:<section>:<part>:<first 16 hex
// of sha256>:<stamp>. The stamp (when the set was queued, unix seconds) is
// there because Engram keeps a key for good: a section that changes back to
// an earlier state (a container stopped and started again) must be heard
// again, which the same key would not be. A resend of a queued event keeps
// its key.
func Key(section string, part int, sum string, stamp int64) string {
	short := sum
	if len(short) > 16 {
		short = short[:16]
	}
	return fmt.Sprintf("state:%s:%d:%s:%d", section, part, short, stamp)
}

// Raw turns a list of values into the items of a section.
func Raw[T any](list []T) []json.RawMessage {
	out := make([]json.RawMessage, 0, len(list))
	for _, v := range list {
		b, err := json.Marshal(v)
		if err != nil {
			continue
		}
		out = append(out, b)
	}
	return out
}

// RawMeta marshals a meta object.
func RawMeta(m map[string]any) json.RawMessage {
	if m == nil {
		return json.RawMessage("{}")
	}
	b, err := json.Marshal(m)
	if err != nil {
		return json.RawMessage("{}")
	}
	return b
}
