package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseTime(t *testing.T) {
	ref := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	cases := map[string]time.Time{
		"":                          ref,
		"now":                       ref,
		"-1h":                       ref.Add(-time.Hour),
		"90m":                       ref.Add(-90 * time.Minute),
		"2d":                        ref.Add(-48 * time.Hour),
		"2026-10-19T10:00:00Z":      ref.Add(-2 * time.Hour),
		"2026-10-19T12:00:00+02:00": ref.Add(-2 * time.Hour),
		"2026-10-19T09:30":          time.Date(2026, 10, 19, 9, 30, 0, 0, time.UTC),
		"1792400000":                time.Unix(1792400000, 0).UTC(),
	}
	for in, want := range cases {
		got, err := ParseTime(in, ref)
		if err != nil || !got.Equal(want) {
			t.Errorf("ParseTime(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseTime("yesterday", ref); err == nil {
		t.Error("yesterday parsed")
	}
}

func TestParseArgsInterleaved(t *testing.T) {
	fs := newFlags("x", &bytes.Buffer{})
	j := fs.Bool("json", false, "")
	db := fs.String("db", "", "")
	pos, err := parseArgs(fs, []string{`{"metric":"x"}`, "--json", "--db", "/tmp/h.db"})
	if err != nil || !*j || *db != "/tmp/h.db" || len(pos) != 1 || pos[0] != `{"metric":"x"}` {
		t.Fatalf("pos %v json %v db %q err %v", pos, *j, *db, err)
	}
}

// TestCommandsEndToEnd runs the service for a few samples against the real
// /proc of the test's machine, then every read command against what it wrote.
func TestCommandsEndToEnd(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "history.db")
	cfg := filepath.Join(dir, "none.json")
	var out, errOut bytes.Buffer
	if code := Main([]string{"run", "--config", cfg, "--db", db, "--interval", "1s", "--samples", "3"}, &out, &errOut); code != 0 {
		t.Fatalf("run: %d %s", code, errOut.String())
	}
	call := func(args ...string) map[string]any {
		t.Helper()
		var o, e bytes.Buffer
		args = append(args, "--config", cfg, "--db", db, "--json")
		if code := Main(args, &o, &e); code != 0 {
			t.Fatalf("%v: %d %s %s", args, code, e.String(), o.String())
		}
		var v map[string]any
		if err := json.Unmarshal(o.Bytes(), &v); err != nil {
			t.Fatalf("%v: not JSON: %v\n%s", args, err, o.String())
		}
		return v
	}
	st := call("status")
	if st["sample_at"] == nil || st["now"].(map[string]any)["memory_pct"] == nil {
		t.Fatalf("status: %v", st)
	}
	if st["enrolment"].(map[string]any)["enrolled"] != false {
		t.Errorf("enrolment: %v", st["enrolment"])
	}
	q := call("query", `{"metric":"memory_pct","from":"-5m","to":"now","points":10}`)
	if q["tier"] != "10s" || q["summary"].(map[string]any)["max_at"] == nil {
		t.Fatalf("query: %v", q)
	}
	pk := call("peaks", "--from", "-5m", "--metric", "load*")
	if ms := pk["metrics"].([]any); len(ms) != 3 {
		t.Fatalf("peaks of load*: %v", pk)
	}
	top := call("top")
	if len(top["by_memory"].([]any)) == 0 {
		t.Fatalf("top: %v", top)
	}
	m := call("metrics")
	if len(m["metrics"].([]any)) < 5 {
		t.Fatalf("metrics: %v", m)
	}

	// Errors: a --json caller gets {"error": ...} on stdout and exit 1.
	var o, e bytes.Buffer
	if code := Main([]string{"query", "--db", db, "--config", cfg, "--json", `{"metric":"no_such"}`}, &o, &e); code != 1 || !strings.Contains(o.String(), `"error"`) {
		t.Fatalf("unknown metric: %d %q", code, o.String())
	}
	o.Reset()
	if code := Main([]string{"status", "--db", filepath.Join(dir, "missing.db"), "--config", cfg}, &o, &e); code != 1 {
		t.Fatalf("missing db: %d", code)
	}
	// Human output works too.
	o.Reset()
	if code := Main([]string{"status", "--db", db, "--config", cfg}, &o, &e); code != 0 || !strings.Contains(o.String(), "last hour") {
		t.Fatalf("status text: %s", o.String())
	}
}
