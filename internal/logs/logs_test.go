package logs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMask(t *testing.T) {
	cases := []struct{ in, want string }{
		{"connecting to postgres://app:s3cr3tP4ss@db:5432/app", "connecting to postgres://app:[redacted: url password]@db:5432/app"},
		{"DB_PASSWORD=hunter22 started", "DB_PASSWORD=[redacted: secret] started"},
		{`{"api_key": "abcdef123456", "user": "x"}`, `{"api_key": "[redacted: secret]", "user": "x"}`},
		{"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N", "Authorization: Bearer [redacted: jwt]"},
		{"authorization: bearer 0123456789abcdefOPAQUE", "authorization: bearer [redacted: bearer token]"},
		{"token ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ used", "token [redacted: github token] used"},
		{"key AKIAIOSFODNN7EXAMPLE", "key [redacted: aws key]"},
		{"sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123", "[redacted: api key]"},
		{"stripe sk_live_abcdefghijklmnop1234", "stripe [redacted: stripe key]"},
		{"jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N", "jwt [redacted: jwt]"},
		{"-----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNzaC1rZXk -----END OPENSSH PRIVATE KEY-----", "[redacted: private key]"},
		{"secret=[redacted: x] stays", "secret=[redacted: x] stays"},
		// Ordinary lines stay as they are.
		{"GET /index.html 200 1234 0.003s", "GET /index.html 200 1234 0.003s"},
		{"Failed password for invalid user admin from 1.2.3.4 port 22 ssh2", "Failed password for invalid user admin from 1.2.3.4 port 22 ssh2"},
		{"commit 3f2b8c1e5a4d4e6f9b7a1c2d3e4f5a6b", "commit 3f2b8c1e5a4d4e6f9b7a1c2d3e4f5a6b"},
	}
	for _, c := range cases {
		got, _ := Mask(c.in)
		if got != c.want {
			t.Errorf("Mask(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
	if _, n := Mask("a password=x1y2z3 and token=abc123"); n != 2 {
		t.Errorf("count %d", n)
	}
}

func fakeRunner(lines int, record *[]string) Runner {
	return func(_ context.Context, name string, args ...string) ([]byte, error) {
		*record = append(*record, name+" "+strings.Join(args, " "))
		var b strings.Builder
		for i := 1; i <= lines; i++ {
			fmt.Fprintf(&b, "2026-10-19T12:00:%02d web01 app[1]: line %d password=pw%d\n", i%60, i, i)
		}
		return []byte(b.String()), nil
	}
}

func TestUnitAndContainer(t *testing.T) {
	var calls []string
	r, err := ReadWith(context.Background(), Request{Unit: "nginx.service", Lines: 3, Since: "1h"}, fakeRunner(3, &calls))
	if err != nil {
		t.Fatal(err)
	}
	if calls[0] != "journalctl --no-pager -q -o short-iso -u nginx.service -n 3 --since -1h" {
		t.Errorf("journalctl call %q", calls[0])
	}
	if len(r.Lines) != 3 || r.Masked != 3 || !strings.HasSuffix(r.Lines[2], "password=[redacted: secret]") || r.Source != "journal:nginx.service" {
		t.Fatalf("%+v", r)
	}
	// --grep reads further back and keeps the newest matches.
	calls = nil
	r, err = ReadWith(context.Background(), Request{Container: "web-php", Lines: 2, Grep: "line 9"}, fakeRunner(100, &calls))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(calls[0], "docker logs --timestamps --tail 20000 -- web-php") {
		t.Errorf("docker call %q", calls[0])
	}
	if len(r.Lines) != 2 || !strings.Contains(r.Lines[1], "line 99") || !r.Truncated {
		t.Fatalf("grep %+v", r)
	}
	// Names that are not names are refused before anything runs.
	for _, bad := range []Request{{Unit: "x; rm -rf /"}, {Container: "-v"}, {Unit: "a", Since: "$(id)"}, {}, {Unit: "a", File: "/var/log/x"}} {
		calls = nil
		if _, err := ReadWith(context.Background(), bad, fakeRunner(1, &calls)); err == nil || len(calls) != 0 {
			t.Errorf("%+v: err %v, calls %v", bad, err, calls)
		}
	}
	// A failing command says why.
	_, err = ReadWith(context.Background(), Request{Container: "x"}, func(context.Context, string, ...string) ([]byte, error) {
		return []byte("permission denied while trying to connect to the Docker daemon socket"), errors.New("exit status 1")
	})
	if err == nil || !strings.Contains(err.Error(), "group docker") {
		t.Errorf("docker refusal: %v", err)
	}
}

func TestLimits(t *testing.T) {
	var calls []string
	r, err := ReadWith(context.Background(), Request{Unit: "a.service", Lines: 5000}, fakeRunner(600, &calls))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Lines) != MaxLines || !r.Truncated {
		t.Fatalf("lines %d", len(r.Lines))
	}
	// 500 lines of 1 KB: cut to 64 KB, newest kept.
	long := strings.Repeat("x", 1023)
	r, err = ReadWith(context.Background(), Request{Unit: "a.service", Lines: 500}, func(context.Context, string, ...string) ([]byte, error) {
		var b strings.Builder
		for i := 0; i < 500; i++ {
			fmt.Fprintf(&b, "%03d%s\n", i, long[3:])
		}
		return []byte(b.String()), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	size := 0
	for _, l := range r.Lines {
		size += len(l) + 1
	}
	if size > MaxBytes || !strings.HasPrefix(r.Lines[len(r.Lines)-1], "499") || !r.Truncated {
		t.Fatalf("size %d, last %q", size, r.Lines[len(r.Lines)-1][:3])
	}
}

func TestFileAllowlist(t *testing.T) {
	dir := t.TempDir()
	logdir := filepath.Join(dir, "log")
	os.MkdirAll(filepath.Join(logdir, "nginx"), 0o755)
	var b strings.Builder
	for i := 1; i <= 3000; i++ {
		fmt.Fprintf(&b, "line %d\n", i)
	}
	os.WriteFile(filepath.Join(logdir, "nginx", "access.log"), []byte(b.String()), 0o644)
	os.WriteFile(filepath.Join(dir, "shadow"), []byte("root:secret\n"), 0o644)
	os.Symlink(filepath.Join(dir, "shadow"), filepath.Join(logdir, "evil.log"))
	allowed := []string{logdir + "/*", logdir + "/*/*"}

	r, err := Read(context.Background(), Request{File: filepath.Join(logdir, "nginx", "access.log"), Lines: 2, Allowed: allowed})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Lines) != 2 || r.Lines[0] != "line 2999" || r.Lines[1] != "line 3000" {
		t.Fatalf("tail %v", r.Lines)
	}
	for _, p := range []string{filepath.Join(logdir, "evil.log"), filepath.Join(dir, "shadow"), filepath.Join(logdir, "nginx", "..", "..", "shadow"), "relative.log"} {
		if _, err := Read(context.Background(), Request{File: p, Allowed: allowed}); err == nil {
			t.Errorf("%s was read", p)
		}
	}
}
