package snapshot

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// User is one account that can log in, with its groups and its sudo.
type User struct {
	Login  string   `json:"login"`
	UID    int      `json:"uid"`
	Shell  string   `json:"shell"`
	Groups []string `json:"groups"` // primary group name and every /etc/group membership, sorted
	Sudo   string   `json:"sudo"`   // nopasswd, password, none
}

// Key is one key in a user's authorized_keys: its fingerprint, never the key.
type Key struct {
	Login       string  `json:"login"`
	Type        string  `json:"type"`
	Fingerprint string  `json:"fingerprint"` // SHA256:<base64 without padding of sha256(key blob)>
	Comment     *string `json:"comment"`
	Options     bool    `json:"options"` // the line had an options prefix (from="...", command="...")
}

func noLogin(shell string) bool {
	switch filepath.Base(shell) {
	case "nologin", "false", "sync", "shutdown", "halt":
		return true
	}
	return shell == ""
}

// readLimited reads a regular file of at most max bytes, without blocking
// on a FIFO or device someone put in its place.
func readLimited(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
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
	return io.ReadAll(io.LimitReader(f, max))
}

func lines(b []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

// Users lists the accounts in /etc/passwd whose shell lets them log in,
// plus root, with their groups and sudo. homes maps each login to its home
// directory (for SSHKeys; not part of the output).
func (e Env) Users() ([]User, map[string]string, *string) {
	users := []User{}
	homes := map[string]string{}
	var errs []string
	pw, err := readLimited(e.path("etc/passwd"), 8<<20)
	if err != nil {
		return users, homes, errp(fmt.Errorf("/etc/passwd: %w", err))
	}
	gidName := map[string]string{}
	members := map[string][]string{} // login -> groups listing it
	if gb, err := readLimited(e.path("etc/group"), 8<<20); err != nil {
		errs = append(errs, "/etc/group: "+err.Error())
	} else {
		for _, l := range lines(gb) {
			f := strings.Split(l, ":")
			if len(f) < 4 || strings.HasPrefix(l, "#") {
				continue
			}
			gidName[f[2]] = f[0]
			for _, m := range strings.Split(f[3], ",") {
				if m = strings.TrimSpace(m); m != "" {
					members[m] = append(members[m], f[0])
				}
			}
		}
	}
	rules, serr := e.sudoRules()
	errs = append(errs, serr...)
	for _, l := range lines(pw) {
		f := strings.Split(l, ":")
		if len(f) < 7 || strings.HasPrefix(l, "#") {
			continue
		}
		login, shell := f[0], strings.TrimSpace(f[6])
		if login != "root" && noLogin(shell) {
			continue
		}
		uid, _ := strconv.Atoi(f[2])
		set := map[string]bool{}
		if n, ok := gidName[f[3]]; ok {
			set[n] = true
		}
		for _, g := range members[login] {
			set[g] = true
		}
		groups := make([]string, 0, len(set))
		for g := range set {
			groups = append(groups, g)
		}
		sort.Strings(groups)
		u := User{Login: login, UID: uid, Shell: shell, Groups: groups, Sudo: sudoFor(login, groups, rules)}
		users = append(users, u)
		homes[login] = f[5]
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Login < users[j].Login })
	return users, homes, joinErrs(errs)
}

// sudoRule is one rule line of sudoers, as much of it as is judged.
type sudoRule struct {
	who      string // a login, or %group
	nopasswd bool
}

// sudoRules reads /etc/sudoers and /etc/sudoers.d/* (sudo's own
// includedir skips names with a dot or ending in ~). Only lines whose
// runas and command lists contain ALL count: such a line gives sudo.
func (e Env) sudoRules() ([]sudoRule, []string) {
	var errs []string
	files := []string{e.path("etc/sudoers")}
	if ents, err := os.ReadDir(e.path("etc/sudoers.d")); err == nil {
		for _, en := range ents {
			n := en.Name()
			if strings.Contains(n, ".") || strings.HasSuffix(n, "~") || en.IsDir() {
				continue
			}
			files = append(files, e.path(filepath.Join("etc/sudoers.d", n)))
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, "/etc/sudoers.d: "+err.Error())
	}
	var rules []sudoRule
	for _, p := range files {
		b, err := readLimited(p, 4<<20)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, strings.TrimPrefix(p, strings.TrimSuffix(e.Root, "/"))+": "+err.Error())
			}
			continue
		}
		var cont string
		for _, l := range lines(b) {
			l = strings.TrimSpace(l)
			if strings.HasSuffix(l, "\\") {
				cont += strings.TrimSuffix(l, "\\") + " "
				continue
			}
			l, cont = cont+l, ""
			if l == "" || l[0] == '#' || l[0] == '@' {
				continue
			}
			f := strings.Fields(l)
			if len(f) < 2 || f[0] == "Defaults" || strings.HasPrefix(f[0], "Defaults") || strings.HasSuffix(f[0], "_Alias") {
				continue
			}
			if !strings.Contains(l, "ALL") {
				continue
			}
			rules = append(rules, sudoRule{who: f[0], nopasswd: strings.Contains(l, "NOPASSWD:")})
		}
	}
	return rules, errs
}

func sudoFor(login string, groups []string, rules []sudoRule) string {
	res := "none"
	if login == "root" {
		res = "password"
	}
	for _, r := range rules {
		match := r.who == login
		for _, g := range groups {
			if r.who == "%"+g {
				match = true
			}
		}
		if !match {
			continue
		}
		if r.nopasswd {
			return "nopasswd"
		}
		res = "password"
	}
	return res
}

// keyTypes are the public key types OpenSSH accepts in authorized_keys.
var keyTypes = map[string]bool{
	"ssh-ed25519": true, "ssh-rsa": true, "ssh-dss": true,
	"ecdsa-sha2-nistp256": true, "ecdsa-sha2-nistp384": true, "ecdsa-sha2-nistp521": true,
	"sk-ssh-ed25519@openssh.com": true, "sk-ecdsa-sha2-nistp256@openssh.com": true,
	"ssh-ed25519-cert-v01@openssh.com": true, "ssh-rsa-cert-v01@openssh.com": true,
	"ecdsa-sha2-nistp256-cert-v01@openssh.com": true, "ecdsa-sha2-nistp384-cert-v01@openssh.com": true,
	"ecdsa-sha2-nistp521-cert-v01@openssh.com": true, "sk-ssh-ed25519-cert-v01@openssh.com": true,
	"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com": true,
}

// splitOptions takes the options prefix off a line: everything up to the
// first space outside double quotes.
func splitOptions(l string) (string, string) {
	inQ := false
	for i := 0; i < len(l); i++ {
		switch c := l[i]; {
		case c == '\\' && inQ && i+1 < len(l):
			i++
		case c == '"':
			inQ = !inQ
		case (c == ' ' || c == '\t') && !inQ:
			return l[:i], strings.TrimLeft(l[i:], " \t")
		}
	}
	return l, ""
}

// ParseKeyLine reads one authorized_keys line. ok is false for a comment,
// a blank line, or anything that is not a well-formed key.
func ParseKeyLine(l string) (k Key, ok bool) {
	l = strings.TrimSpace(l)
	if l == "" || l[0] == '#' {
		return k, false
	}
	f := strings.Fields(l)
	if !keyTypes[f[0]] {
		_, rest := splitOptions(l)
		if rest == "" {
			return k, false
		}
		k.Options = true
		l = rest
		f = strings.Fields(l)
	}
	if len(f) < 2 || !keyTypes[f[0]] {
		return k, false
	}
	blob, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil || len(blob) < 4 {
		return k, false
	}
	n := binary.BigEndian.Uint32(blob[:4])
	if uint64(n) > uint64(len(blob)-4) || string(blob[4:4+n]) != f[0] {
		return k, false
	}
	sum := sha256.Sum256(blob)
	k.Type = f[0]
	k.Fingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	// The comment is what follows the key, as written.
	_, after, _ := strings.Cut(l, f[1])
	if c := strings.TrimSpace(after); c != "" {
		k.Comment = &c
	}
	return k, true
}

// SSHKeys reads ~/.ssh/authorized_keys and authorized_keys2 of every user.
func (e Env) SSHKeys(users []User, homes map[string]string) Section {
	keys := []Key{}
	var errs []string
	for _, u := range users {
		home := homes[u.Login]
		if home == "" || !strings.HasPrefix(home, "/") {
			continue
		}
		for _, name := range []string{"authorized_keys", "authorized_keys2"} {
			p := e.path(filepath.Join(home, ".ssh", name))
			b, err := readLimited(p, 1<<20)
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ENOTDIR) {
					errs = append(errs, filepath.Join(home, ".ssh", name)+": "+err.Error())
				}
				continue
			}
			for _, l := range lines(b) {
				if k, ok := ParseKeyLine(l); ok {
					k.Login = u.Login
					keys = append(keys, k)
				}
			}
		}
	}
	sort.SliceStable(keys, func(i, j int) bool {
		if keys[i].Login != keys[j].Login {
			return keys[i].Login < keys[j].Login
		}
		if keys[i].Fingerprint != keys[j].Fingerprint {
			return keys[i].Fingerprint < keys[j].Fingerprint
		}
		return keys[i].Options && !keys[j].Options
	})
	return Section{Items: keys, Meta: map[string]any{}, Error: joinErrs(errs)}
}
