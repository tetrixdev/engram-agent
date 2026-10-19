package logs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Limits on one answer, whatever is asked.
const (
	MaxLines = 500
	MaxBytes = 64 << 10
	// scanLines is how many lines are read back to find --grep matches in.
	scanLines = 20000
)

// Request is one `engram-agent logs` call. Exactly one of Unit, Container, File.
type Request struct {
	Unit, Container, File string
	Lines                 int
	Since                 string // journalctl/docker form: "2026-10-19 14:00:00", "-1h", "1h"
	Grep                  string // a plain substring, case-sensitive
	// Allowed are the glob patterns a File must match (config log_files).
	Allowed []string
}

// Result is the answer.
type Result struct {
	Source    string   `json:"source"`
	Lines     []string `json:"lines"`
	Truncated bool     `json:"truncated"` // lines were dropped to stay within the limits
	Masked    int      `json:"masked"`    // how many secret-looking strings were replaced
	Note      string   `json:"note,omitempty"`
}

// Runner runs a command and returns its stdout and stderr together.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"LANG=C.UTF-8", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "SYSTEMD_PAGER=", "SYSTEMD_COLORS=0"}
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	return buf.Bytes(), err
}

var (
	unitName      = regexp.MustCompile(`^[A-Za-z0-9@_.:\\-]{1,200}$`)
	containerName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	sinceForm     = regexp.MustCompile(`^[0-9A-Za-z :.+-]{1,40}$`)
)

// Read answers a request with the real commands.
func Read(ctx context.Context, r Request) (*Result, error) { return ReadWith(ctx, r, run) }

// ReadWith answers a request with the given runner (tests replace it).
func ReadWith(ctx context.Context, r Request, runner Runner) (*Result, error) {
	n := 0
	for _, s := range []string{r.Unit, r.Container, r.File} {
		if s != "" {
			n++
		}
	}
	if n != 1 {
		return nil, errors.New("give exactly one of --unit, --container or --file")
	}
	if r.Lines <= 0 {
		r.Lines = 100
	}
	if r.Lines > MaxLines {
		r.Lines = MaxLines
	}
	if r.Since != "" && !sinceForm.MatchString(r.Since) {
		return nil, fmt.Errorf("--since %q: use a time such as \"2026-10-19 14:00\" or a duration such as 1h", r.Since)
	}
	fetch := r.Lines
	if r.Grep != "" {
		fetch = scanLines
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var raw []string
	var source string
	res := &Result{}
	switch {
	case r.Unit != "":
		if !unitName.MatchString(r.Unit) {
			return nil, fmt.Errorf("--unit %q is not a unit name", r.Unit)
		}
		source = "journal:" + r.Unit
		args := []string{"--no-pager", "-q", "-o", "short-iso", "-u", r.Unit, "-n", strconv.Itoa(fetch)}
		if r.Since != "" {
			args = append(args, "--since", journalSince(r.Since))
		}
		out, err := runner(ctx, "journalctl", args...)
		if err != nil {
			return nil, fmt.Errorf("journalctl: %v: %s (reading the journal needs group systemd-journal or adm)", err, firstLine(out))
		}
		raw = splitLines(string(out))
		if len(raw) == 0 {
			res.Note = "no lines: the unit logged nothing in that range, or this user may not read its journal (groups systemd-journal or adm)"
		}
	case r.Container != "":
		if !containerName.MatchString(r.Container) {
			return nil, fmt.Errorf("--container %q is not a container name or id", r.Container)
		}
		source = "docker:" + r.Container
		args := []string{"logs", "--timestamps", "--tail", strconv.Itoa(fetch)}
		if r.Since != "" {
			args = append(args, "--since", strings.TrimPrefix(r.Since, "-"))
		}
		args = append(args, "--", r.Container)
		out, err := runner(ctx, "docker", args...)
		if err != nil {
			msg := firstLine(out)
			if strings.Contains(msg, "permission denied") {
				msg += " (this user may not use docker: it needs group docker)"
			}
			return nil, fmt.Errorf("docker logs: %v: %s", err, msg)
		}
		raw = splitLines(string(out))
	default:
		path, err := allowedFile(r.File, r.Allowed)
		if err != nil {
			return nil, err
		}
		source = "file:" + path
		if r.Since != "" {
			res.Note = "--since is not applied to a file: its lines carry no time this reads"
		}
		raw, err = tailFile(path, fetch)
		if err != nil {
			return nil, err
		}
	}
	res.Source = source
	if r.Grep != "" {
		var keep []string
		for _, l := range raw {
			if strings.Contains(l, r.Grep) {
				keep = append(keep, l)
			}
		}
		raw = keep
	}
	if len(raw) > r.Lines {
		raw = raw[len(raw)-r.Lines:]
		res.Truncated = true
	}
	// Mask, then keep the newest lines within MaxBytes.
	masked := make([]string, len(raw))
	for i, l := range raw {
		m, c := Mask(l)
		masked[i] = m
		res.Masked += c
	}
	size := 0
	start := len(masked)
	for start > 0 && size+len(masked[start-1])+1 <= MaxBytes {
		start--
		size += len(masked[start]) + 1
	}
	if start > 0 {
		res.Truncated = true
		if start == len(masked) && len(masked) > 0 {
			// One line longer than the limit: keep its end.
			l := masked[len(masked)-1]
			masked[len(masked)-1] = l[len(l)-MaxBytes+1:]
			start = len(masked) - 1
		}
	}
	res.Lines = masked[start:]
	if res.Lines == nil {
		res.Lines = []string{}
	}
	return res, nil
}

// journalSince turns "-1h" or "1h" into journalctl's "-1h"; times pass as they are.
func journalSince(s string) string {
	if _, err := time.ParseDuration(strings.TrimPrefix(s, "-")); err == nil && !strings.HasPrefix(s, "-") {
		return "-" + s
	}
	return s
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

func splitLines(s string) []string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// allowedFile checks a path against the allowlist, after resolving symlinks,
// so a link in /var/log cannot point it at /etc/shadow.
func allowedFile(p string, allowed []string) (string, error) {
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("--file %q: give an absolute path", p)
	}
	clean := filepath.Clean(p)
	real, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", fmt.Errorf("--file %s: %v", clean, err)
	}
	ok := func(path string) bool {
		for _, g := range allowed {
			if m, _ := filepath.Match(g, path); m {
				return true
			}
		}
		return false
	}
	if !ok(clean) || !ok(real) {
		return "", fmt.Errorf("--file %s is not among the files logs may read (%s; log_files in the configuration)", clean, strings.Join(allowed, ", "))
	}
	return real, nil
}

// tailFile reads the last n lines of a file, reading back from its end.
func tailFile(path string, n int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	size := fi.Size()
	const chunk = 64 << 10
	var buf []byte
	off := size
	for off > 0 && bytes.Count(buf, []byte{'\n'}) <= n && int64(len(buf)) < 16<<20 {
		step := int64(chunk)
		if off < step {
			step = off
		}
		off -= step
		b := make([]byte, step)
		if _, err := f.ReadAt(b, off); err != nil && err != io.EOF {
			return nil, err
		}
		buf = append(b, buf...)
	}
	lines := splitLines(string(buf))
	if off > 0 && len(lines) > 0 {
		lines = lines[1:] // the first is probably cut
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines, nil
}
