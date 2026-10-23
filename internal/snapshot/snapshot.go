// Package snapshot is the one part of engram-agent that runs as root: a
// oneshot, started by a systemd timer, that reads what the unprivileged
// agent cannot (the firewall, the docker socket, sudoers, every user's
// authorized_keys, tailscale's status) and writes it into one file the agent
// reads. It takes no input, opens no network connection (only local unix
// sockets and netlink) and writes nothing but that one file.
package snapshot

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// DefaultDir is where the snapshot is written: root-owned, group
// engram-agent, and outside the agent's own /var/lib/engram-agent so the
// unprivileged agent cannot swap the directory under root.
const DefaultDir = "/var/lib/engram-agent-snapshot"

// FileName is the snapshot file inside the directory.
const FileName = "state.json"

// Group is the group the file belongs to, so the agent can read it.
const Group = "engram-agent"

// Version is the document's format version.
const Version = 1

// SectionNames are the sections a snapshot holds, in a fixed order.
var SectionNames = []string{"firewall", "containers", "users", "ssh_keys", "tailscale"}

// Document is the whole file.
type Document struct {
	Version      int                `json:"version"`
	CollectedAt  string             `json:"collected_at"`
	AgentVersion string             `json:"agent_version"`
	Sections     map[string]Section `json:"sections"`
}

// Section is one part of the snapshot. A section that could not be read
// carries its own error; the others are unaffected.
type Section struct {
	Items any            `json:"items"`
	Meta  map[string]any `json:"meta"`
	Error *string        `json:"error"`
}

// Env is where the snapshot reads: the filesystem root (tests point it at
// a fixture tree), the docker socket, and how commands are run.
type Env struct {
	Root         string
	DockerSocket string // default <Root>/var/run/docker.sock
	// Run runs a command by its absolute path (as found under Root) and
	// returns its standard output.
	Run func(ctx context.Context, path string, args ...string) ([]byte, error)
	Now func() time.Time
}

// DefaultEnv reads the real host.
func DefaultEnv() Env {
	return Env{Root: "/", Run: runCommand, Now: time.Now}
}

func (e Env) path(p string) string { return filepath.Join(e.Root, p) }

func (e Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e Env) socket() string {
	if e.DockerSocket != "" {
		return e.DockerSocket
	}
	return e.path("var/run/docker.sock")
}

// runCommand runs a program with a fixed environment and a timeout; a
// failure carries the first line of what it wrote to stderr.
func runCommand(ctx context.Context, path string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if msg := firstLineOf(stderr.String()); msg != "" {
			err = fmt.Errorf("%w: %s", err, msg)
		}
	}
	return out, err
}

func firstLineOf(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// lookPath finds a program in the given directories under Root.
func (e Env) lookPath(name string, dirs ...string) string {
	for _, d := range dirs {
		p := e.path(filepath.Join(d, name))
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
			return p
		}
	}
	return ""
}

func errp(err error) *string {
	if err == nil {
		return nil
	}
	s := err.Error()
	return &s
}

func joinErrs(errs []string) *string {
	if len(errs) == 0 {
		return nil
	}
	s := strings.Join(errs, "; ")
	return &s
}

// Collect reads every section. It never fails as a whole.
func (e Env) Collect(ctx context.Context, agentVersion string) Document {
	d := Document{Version: Version, CollectedAt: e.now().UTC().Format(time.RFC3339), AgentVersion: agentVersion, Sections: map[string]Section{}}
	d.Sections["firewall"] = e.Firewall(ctx)
	d.Sections["containers"] = e.Containers(ctx)
	users, homes, uerr := e.Users()
	d.Sections["users"] = Section{Items: users, Meta: map[string]any{}, Error: uerr}
	d.Sections["ssh_keys"] = e.SSHKeys(users, homes)
	d.Sections["tailscale"] = e.Tailscale(ctx)
	return d
}

// Write puts the document into dir/state.json atomically: a new temp file
// in the same directory (O_EXCL|O_NOFOLLOW, so nothing planted there is
// followed or reused), mode 0640, group engram-agent when that group exists,
// fsync, rename over the old file, fsync of the directory. groupID looks the
// group up; nil uses the system's.
func Write(dir string, d Document, groupID func(name string) (int, error)) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	rnd := make([]byte, 8)
	_, _ = rand.Read(rnd)
	tmp := filepath.Join(dir, "."+FileName+"."+hex.EncodeToString(rnd)+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o640)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(b); err != nil {
		return err
	}
	if err := f.Chmod(0o640); err != nil {
		return err
	}
	if groupID == nil {
		groupID = lookupGroup
	}
	if gid, err := groupID(Group); err == nil {
		st, err := f.Stat()
		if err != nil {
			return err
		}
		// The directory is setgid engram-agent, so the file normally has the
		// group already and no chown (which needs CAP_CHOWN) is made.
		if sys, okSys := st.Sys().(*syscall.Stat_t); !okSys || int(sys.Gid) != gid {
			if err := f.Chown(-1, gid); err != nil {
				return fmt.Errorf("give %s group %s: %w (the directory should be setgid %s)", tmp, Group, err, Group)
			}
		}
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, FileName)); err != nil {
		return err
	}
	ok = true
	if df, err := os.Open(dir); err == nil {
		_ = df.Sync()
		df.Close()
	}
	return nil
}

func lookupGroup(name string) (int, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(g.Gid)
}
