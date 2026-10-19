package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// TestEnrolAndReportEndToEnd enrols the agent with a stand-in Engram, runs
// the service for a few samples against the real /proc of the test's
// machine, and checks what arrived: signed reports with host and health,
// and the server.observed event for the new enrolment.
func TestEnrolAndReportEndToEnd(t *testing.T) {
	var mu sync.Mutex
	var pub ed25519.PublicKey
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/agent/v1/enrol":
			var req map[string]string
			json.Unmarshal(body, &req)
			raw, _ := base64.StdEncoding.DecodeString(req["public_key"])
			pub = raw
			if req["code"] != "ABCD-EFGH-JKLM" || req["hostname"] == "" || req["arch"] == "" {
				w.WriteHeader(400)
				return
			}
			w.Write([]byte(`{"agent_id":"a-1","report_every_s":60}`))
		case "/agent/v1/report":
			sum := sha256.Sum256(body)
			signed := "engram-agent-v1\n" + r.Header.Get("X-Engram-Agent") + "\n" + r.Header.Get("X-Engram-Time") + "\n" + hex.EncodeToString(sum[:])
			sig, _ := base64.StdEncoding.DecodeString(r.Header.Get("X-Engram-Signature"))
			if _, err := strconv.ParseInt(r.Header.Get("X-Engram-Time"), 10, 64); err != nil || !ed25519.Verify(pub, []byte(signed), sig) {
				t.Errorf("a report that does not verify")
				w.WriteHeader(401)
				return
			}
			var m map[string]any
			json.Unmarshal(body, &m)
			bodies = append(bodies, m)
			w.Write([]byte(`{"ok":true,"accepted":0,"report_every_s":60}`))
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	os.WriteFile(cfgPath, []byte(`{"state_dir":"`+dir+`"}`), 0o644)
	var out, errOut bytes.Buffer
	if code := Main([]string{"enrol", "--config", cfgPath, "--url", srv.URL, "--code", "ABCD-EFGH-JKLM"}, &out, &errOut); code != 0 {
		t.Fatalf("enrol: %s %s", out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "fingerprint ") {
		t.Fatalf("enrol output %q", out.String())
	}
	if fi, _ := os.Stat(filepath.Join(dir, "agent.key")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v", fi.Mode())
	}
	// Enrolling twice is refused.
	if code := Main([]string{"enrol", "--config", cfgPath, "--url", srv.URL, "--code", "ABCD-EFGH-JKLM"}, &out, &errOut); code == 0 {
		t.Fatal("enrolled twice")
	}
	errOut.Reset()
	if code := Main([]string{"run", "--config", cfgPath, "--interval", "1s", "--samples", "4"}, &out, &errOut); code != 0 {
		t.Fatalf("run: %s", errOut.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) == 0 {
		t.Fatalf("no report arrived; log:\n%s", errOut.String())
	}
	first := bodies[0]
	host, _ := first["host"].(map[string]any)
	if host == nil || host["hostname"] == "" || host["arch"] == "" {
		t.Fatalf("first report's host: %v", first)
	}
	var observed map[string]any
	for _, b := range bodies {
		evs, _ := b["events"].([]any)
		for _, e := range evs {
			ev := e.(map[string]any)
			if ev["type"] == "server.observed" && ev["ref"] == "host" && ev["key"] != "" {
				observed = ev["state"].(map[string]any)
			}
		}
	}
	if observed == nil {
		t.Fatalf("no server.observed among %d reports; log:\n%s", len(bodies), errOut.String())
	}
	if _, ok := observed["packages_sha256"]; !ok {
		t.Fatalf("observed %v", observed)
	}
	if _, ok := observed["packages"]; ok {
		t.Fatal("the package list was sent")
	}
	// status shows the enrolment and the accepted report.
	out.Reset()
	if code := Main([]string{"status", "--config", cfgPath, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("status: %s", errOut.String())
	}
	var st Status
	json.Unmarshal(out.Bytes(), &st)
	if !st.Enrolment.Enrolled || st.Enrolment.AgentID != "a-1" || st.Enrolment.Report != "ok" || len(st.Enrolment.Fingerprint) != 19 {
		t.Fatalf("status enrolment %+v", st.Enrolment)
	}
}
