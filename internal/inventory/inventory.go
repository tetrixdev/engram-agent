// Package inventory describes what is on a server, without root: the OS and
// kernel, packages and pending updates, failed units, listening ports, login
// users, sshd's configured settings and running containers. It is what the
// agent's server.observed event summarises and what `engram-agent inventory`
// prints in full.
package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tetrixdev/engram-agent/internal/collect"
)

// Env is where the inventory reads: the filesystem root (for /etc and /var),
// /proc, the cgroup root, and how commands are run (tests replace it).
type Env struct {
	Root   string
	Proc   string
	Cgroup string
	Run    func(ctx context.Context, name string, args ...string) ([]byte, error)
	Statfs func(path string) (collect.FsStat, error)
}

// DefaultEnv reads the real host.
func DefaultEnv() Env {
	return Env{Root: "/", Proc: "/proc", Cgroup: "/sys/fs/cgroup", Run: runCommand, Statfs: collect.New(collect.DefaultPaths()).Statfs}
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	return cmd.Output()
}

func (e Env) path(p string) string { return filepath.Join(e.Root, p) }

// SSH is sshd's configured settings, from its files.
type SSH struct {
	Port         int      `json:"port"`
	Ports        []int    `json:"ports,omitempty"`
	PasswordAuth *bool    `json:"password_auth"` // null when a file that could set it is unreadable
	RootLogin    *string  `json:"root_login"`    // PermitRootLogin as written, or OpenSSH's default
	Unreadable   []string `json:"unreadable,omitempty"`
	Source       string   `json:"source"`
}

// Summary is the server.observed state: its keys are exactly the ones the
// Servers app declares, so nothing else may be added here.
type Summary struct {
	Hostname             string   `json:"hostname"`
	OS                   string   `json:"os"`
	Kernel               string   `json:"kernel"`
	KernelNewest         *string  `json:"kernel_newest"`
	Arch                 string   `json:"arch"`
	CPUCores             int      `json:"cpu_cores"`
	MemoryBytes          int64    `json:"memory_bytes"`
	DiskBytes            int64    `json:"disk_bytes"`
	BootTime             string   `json:"boot_time"`
	RebootRequired       bool     `json:"reboot_required"`
	RebootPackages       []string `json:"reboot_packages"`
	PackagesCount        int      `json:"packages_count"`
	PackagesSHA256       string   `json:"packages_sha256"`
	UpdatesCount         *int     `json:"updates_count"`
	SecurityUpdatesCount *int     `json:"security_updates_count"`
	UnattendedUpgrades   *bool    `json:"unattended_upgrades"`
	FailedUnits          []string `json:"failed_units"`
	Listening            []string `json:"listening"`
	LoginUsers           []string `json:"login_users"`
	SSH                  SSHState `json:"ssh"`
	ContainersCount      int      `json:"containers_count"`
	AgentVersion         string   `json:"agent_version"`
	SSHHostKeys          []string `json:"ssh_host_keys"`
}

// SSHState is the ssh object of the summary.
type SSHState struct {
	Port         int     `json:"port"`
	PasswordAuth *bool   `json:"password_auth"`
	RootLogin    *string `json:"root_login"`
}

// Updates are the pending upgrades apt would install.
type Updates struct {
	Count    int      `json:"count"`
	Security int      `json:"security"`
	Packages []Update `json:"packages"`
	Error    string   `json:"error,omitempty"`
}

// Update is one pending upgrade.
type Update struct {
	Name     string `json:"name"`
	From     string `json:"from"`
	To       string `json:"to"`
	Origin   string `json:"origin"`
	Security bool   `json:"security"`
}

// Port is one listening socket.
type Port struct {
	Proto   string `json:"proto"` // tcp, udp
	Port    int    `json:"port"`
	Address string `json:"address"`
	Local   bool   `json:"loopback_only"`
}

// Kernel is the running and installed kernels.
type Kernel struct {
	Running   string   `json:"running"`
	Installed []string `json:"installed"`
	Newest    *string  `json:"newest"`
}

// Sections lists what `inventory --section` accepts.
var Sections = []string{"summary", "os", "kernel", "packages", "updates", "services", "ports", "users", "ssh", "containers", "state"}

// OSRelease is PRETTY_NAME (or NAME VERSION) of /etc/os-release.
func (e Env) OSRelease() string {
	kv := map[string]string{}
	lines := collect.ReadLines(e.path("etc/os-release"))
	if lines == nil {
		lines = collect.ReadLines(e.path("usr/lib/os-release"))
	}
	for _, l := range lines {
		k, v, ok := strings.Cut(l, "=")
		if ok {
			kv[k] = strings.Trim(v, `"'`)
		}
	}
	if p := kv["PRETTY_NAME"]; p != "" {
		return p
	}
	return strings.TrimSpace(kv["NAME"] + " " + kv["VERSION"])
}

func firstLine(path string) string {
	l := collect.ReadLines(path)
	if len(l) == 0 {
		return ""
	}
	return strings.TrimSpace(l[0])
}

// Hostname is the kernel's host name.
func (e Env) Hostname() string {
	if h := firstLine(filepath.Join(e.Proc, "sys/kernel/hostname")); h != "" {
		return h
	}
	h, _ := os.Hostname()
	return h
}

// RunningKernel is the running kernel's release, e.g. 6.8.0-45-generic.
func (e Env) RunningKernel() string { return firstLine(filepath.Join(e.Proc, "sys/kernel/osrelease")) }

var kernelPkg = regexp.MustCompile(`^linux-image-(?:unsigned-)?(\d+\.\d+.*)$`)

// Kernel lists the installed kernel images and the newest of them.
func (e Env) Kernel(pkgs []Package) Kernel {
	k := Kernel{Running: e.RunningKernel(), Installed: []string{}}
	type kv struct{ release, version string }
	var all []kv
	for _, p := range pkgs {
		if m := kernelPkg.FindStringSubmatch(p.Name); m != nil {
			all = append(all, kv{m[1], p.Version})
			k.Installed = append(k.Installed, m[1])
		}
	}
	sort.Slice(all, func(i, j int) bool { return CompareVersions(all[i].version, all[j].version) < 0 })
	if len(all) > 0 {
		n := all[len(all)-1].release
		k.Newest = &n
	}
	sort.Strings(k.Installed)
	return k
}

// Reboot says whether a reboot is required and which packages asked for it.
func (e Env) Reboot() (bool, []string) {
	_, err := os.Stat(e.path("var/run/reboot-required"))
	if err != nil {
		_, err = os.Stat(e.path("run/reboot-required"))
	}
	pkgs := []string{}
	if err != nil {
		return false, pkgs
	}
	seen := map[string]bool{}
	for _, f := range []string{"var/run/reboot-required.pkgs", "run/reboot-required.pkgs"} {
		for _, l := range collect.ReadLines(e.path(f)) {
			if l = strings.TrimSpace(l); l != "" && !seen[l] {
				seen[l] = true
				pkgs = append(pkgs, l)
			}
		}
	}
	sort.Strings(pkgs)
	return true, pkgs
}

// Packages reads dpkg's status file.
func (e Env) Packages() ([]Package, error) {
	p, err := ReadDpkgStatus(e.path("var/lib/dpkg/status"))
	sort.Slice(p, func(i, j int) bool { return p[i].Name+":"+p[i].Arch < p[j].Name+":"+p[j].Arch })
	return p, err
}

// PackagesDigest is the count and a sha256 over "name\tversion\tarch\n" of
// every package, sorted: it changes exactly when the list does.
func PackagesDigest(p []Package) (int, string) {
	h := sha256.New()
	for _, x := range p {
		fmt.Fprintf(h, "%s\t%s\t%s\n", x.Name, x.Version, x.Arch)
	}
	return len(p), hex.EncodeToString(h.Sum(nil))
}

// DpkgStamp is the status file's modification time: the agent re-reads the
// inventory when it changes.
func (e Env) DpkgStamp() time.Time {
	fi, err := os.Stat(e.path("var/lib/dpkg/status"))
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}

var instLine = regexp.MustCompile(`^Inst (\S+) \[([^\]]+)\] \((\S+) (.*?)(?: \[[^\]]*\])?\)`)

// ParseAptSimulation reads `apt-get -s dist-upgrade`: every "Inst name [old]
// (new origin [arch])" line is an upgrade (a line without [old] is a new
// package pulled in, not an update). Security when an origin names a
// -security pocket.
func ParseAptSimulation(out string) Updates {
	u := Updates{Packages: []Update{}}
	for _, l := range strings.Split(out, "\n") {
		m := instLine.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		up := Update{Name: m[1], From: m[2], To: m[3], Origin: m[4]}
		up.Security = strings.Contains(m[4], "-security") || strings.Contains(m[4], "Debian-Security")
		u.Packages = append(u.Packages, up)
		u.Count++
		if up.Security {
			u.Security++
		}
	}
	return u
}

// Updates asks apt, as this user, what an upgrade would install. It reads
// apt's lists as they are: it never refreshes them (that needs root and is
// the system's own timer's job).
func (e Env) Updates(ctx context.Context) Updates {
	if _, err := os.Stat(e.path("usr/bin/apt-get")); err != nil && e.Root == "/" {
		return Updates{Packages: []Update{}, Error: "apt-get not found: not an apt system"}
	}
	out, err := e.Run(ctx, "apt-get", "-s", "-q", "-o", "Debug::NoLocking=true", "dist-upgrade")
	if err != nil && len(out) == 0 {
		return Updates{Packages: []Update{}, Error: "apt-get -s dist-upgrade: " + err.Error()}
	}
	return ParseAptSimulation(string(out))
}

// UnattendedUpgrades is true when APT::Periodic::Unattended-Upgrade is on
// and the package is installed, false when either is off, null when the
// system has no apt configuration.
func (e Env) UnattendedUpgrades(pkgs []Package) *bool {
	files, _ := filepath.Glob(e.path("etc/apt/apt.conf.d/*"))
	if len(files) == 0 {
		return nil
	}
	installed := false
	for _, p := range pkgs {
		if p.Name == "unattended-upgrades" {
			installed = true
		}
	}
	re := regexp.MustCompile(`APT::Periodic::Unattended-Upgrade\s+"(\d+)"`)
	on := false
	sort.Strings(files)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			on = m[1] != "0" // the last file to set it wins, as apt reads them in order
		}
	}
	r := on && installed
	return &r
}

// FailedUnits asks systemd which units failed.
func (e Env) FailedUnits(ctx context.Context) ([]string, error) {
	out, err := e.Run(ctx, "systemctl", "--failed", "--plain", "--no-legend", "--no-pager")
	if err != nil && len(out) == 0 {
		return []string{}, fmt.Errorf("systemctl --failed: %w", err)
	}
	return ParseFailedUnits(string(out)), nil
}

// ParseFailedUnits reads the unit names from `systemctl --failed --plain --no-legend`.
func ParseFailedUnits(out string) []string {
	units := []string{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimPrefix(strings.TrimSpace(l), "●"))
		if len(f) > 0 && strings.Contains(f[0], ".") {
			units = append(units, f[0])
		}
	}
	sort.Strings(units)
	return units
}

// Ports reads the listening sockets from /proc/net. Process names need root
// and are not read.
func (e Env) Ports() []Port {
	var out []Port
	seen := map[string]bool{}
	for _, src := range []struct{ file, proto, state string }{
		{"tcp", "tcp", "0A"}, {"tcp6", "tcp", "0A"}, {"udp", "udp", "07"}, {"udp6", "udp", "07"},
	} {
		for i, l := range collect.ReadLines(filepath.Join(e.Proc, "net", src.file)) {
			f := strings.Fields(l)
			if i == 0 || len(f) < 4 || f[3] != src.state {
				continue
			}
			if src.proto == "udp" && !strings.HasSuffix(f[2], ":0000") {
				continue // a connected UDP socket, not a listener
			}
			addr, port := decodeAddr(f[1])
			if port == 0 {
				continue
			}
			p := Port{Proto: src.proto, Port: port, Address: addr, Local: isLoopback(addr)}
			k := fmt.Sprintf("%s/%s/%d", p.Proto, p.Address, p.Port)
			if !seen[k] {
				seen[k] = true
				out = append(out, p)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Proto != out[j].Proto {
			return out[i].Proto < out[j].Proto
		}
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Address < out[j].Address
	})
	return out
}

// Listening is the summary's list: "tcp/22" for every port some non-loopback
// address listens on, sorted by protocol and port. Ports only on 127.0.0.1
// or ::1 cannot be reached from outside and are left out.
func Listening(ports []Port) []string {
	seen := map[string]bool{}
	type pp struct {
		proto string
		port  int
	}
	var list []pp
	for _, p := range ports {
		k := fmt.Sprintf("%s/%d", p.Proto, p.Port)
		if p.Local || seen[k] {
			continue
		}
		seen[k] = true
		list = append(list, pp{p.Proto, p.Port})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].proto != list[j].proto {
			return list[i].proto < list[j].proto
		}
		return list[i].port < list[j].port
	})
	out := []string{}
	for _, x := range list {
		out = append(out, fmt.Sprintf("%s/%d", x.proto, x.port))
	}
	return out
}

func decodeAddr(s string) (string, int) {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0
	}
	port, _ := strconv.ParseUint(p, 16, 16)
	b, err := hex.DecodeString(h)
	if err != nil {
		return "", int(port)
	}
	// /proc/net prints each 32-bit word in host (little-endian) byte order.
	for i := 0; i+4 <= len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	if len(b) == 4 {
		return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3]), int(port)
	}
	if len(b) == 16 {
		if isV4Mapped(b) {
			return fmt.Sprintf("%d.%d.%d.%d", b[12], b[13], b[14], b[15]), int(port)
		}
		var parts []string
		for i := 0; i < 16; i += 2 {
			parts = append(parts, strconv.FormatUint(uint64(b[i])<<8|uint64(b[i+1]), 16))
		}
		return compressV6(parts), int(port)
	}
	return h, int(port)
}

func isV4Mapped(b []byte) bool {
	for i := 0; i < 10; i++ {
		if b[i] != 0 {
			return false
		}
	}
	return b[10] == 0xff && b[11] == 0xff
}

func compressV6(parts []string) string {
	s := strings.Join(parts, ":")
	switch s {
	case "0:0:0:0:0:0:0:0":
		return "::"
	case "0:0:0:0:0:0:0:1":
		return "::1"
	}
	return s
}

func isLoopback(a string) bool {
	return strings.HasPrefix(a, "127.") || a == "::1"
}

// EphemeralRange is the kernel's local port range: a listener inside it is
// most likely a passing one, so the ports section leaves such UDP ports out.
func (e Env) EphemeralRange() (int, int) {
	f := strings.Fields(firstLine(filepath.Join(e.Proc, "sys/net/ipv4/ip_local_port_range")))
	if len(f) == 2 {
		lo, err1 := strconv.Atoi(f[0])
		hi, err2 := strconv.Atoi(f[1])
		if err1 == nil && err2 == nil {
			return lo, hi
		}
	}
	return 32768, 60999
}

// LoginUsers are the accounts in /etc/passwd whose shell lets them log in.
func (e Env) LoginUsers() []string {
	users := []string{}
	for _, l := range collect.ReadLines(e.path("etc/passwd")) {
		f := strings.Split(l, ":")
		if len(f) < 7 {
			continue
		}
		sh := strings.TrimSpace(f[6])
		base := filepath.Base(sh)
		if sh == "" || base == "nologin" || base == "false" || base == "sync" || base == "shutdown" || base == "halt" {
			continue
		}
		users = append(users, f[0])
	}
	sort.Strings(users)
	return users
}

// SSHD reads PermitRootLogin, PasswordAuthentication and Port from
// /etc/ssh/sshd_config and the files it Includes, as sshd does: the first
// value of a keyword wins, and Match blocks are conditional so they are not
// read. It is the files as written, not `sshd -T` (which needs root).
func (e Env) SSHD() SSH {
	s := SSH{Source: "/etc/ssh/sshd_config (files, not sshd -T)"}
	seen := map[string]string{}
	// A keyword first met after an unreadable file may have been set in
	// that file first (sshd takes the first value): it is then unknown.
	blind, uncertain := false, map[string]bool{}
	var ports []int
	var read func(path string, depth int) bool
	read = func(path string, depth int) bool {
		b, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				s.Unreadable = append(s.Unreadable, strings.TrimPrefix(path, strings.TrimSuffix(e.Root, "/")))
				blind = true
			}
			return true
		}
		for _, l := range strings.Split(string(b), "\n") {
			l = strings.TrimSpace(l)
			if l == "" || l[0] == '#' {
				continue
			}
			f := strings.Fields(strings.ReplaceAll(l, "=", " "))
			if len(f) < 2 {
				continue
			}
			k := strings.ToLower(f[0])
			switch k {
			case "match":
				return false // everything after a Match line belongs to it
			case "include":
				if depth > 4 {
					continue
				}
				for _, pat := range f[1:] {
					if !strings.HasPrefix(pat, "/") {
						pat = "/etc/ssh/" + pat
					}
					matches, _ := filepath.Glob(e.path(pat))
					sort.Strings(matches)
					for _, m := range matches {
						if !read(m, depth+1) {
							return false
						}
					}
				}
			case "port":
				if n, err := strconv.Atoi(f[1]); err == nil {
					ports = append(ports, n)
				}
			default:
				if _, ok := seen[k]; !ok {
					seen[k] = strings.ToLower(f[1])
					uncertain[k] = blind
				}
			}
		}
		return true
	}
	if _, err := os.Stat(e.path("etc/ssh/sshd_config")); os.IsNotExist(err) {
		s.Source = "no /etc/ssh/sshd_config: sshd is not installed"
		return s
	}
	read(e.path("etc/ssh/sshd_config"), 0)
	if len(ports) == 0 {
		ports = []int{22}
	}
	s.Port, s.Ports = ports[0], ports
	if v, ok := seen["passwordauthentication"]; ok && !uncertain["passwordauthentication"] {
		b := v == "yes"
		s.PasswordAuth = &b
	} else if !ok && !blind {
		b := true // OpenSSH's default
		s.PasswordAuth = &b
	}
	if v, ok := seen["permitrootlogin"]; ok && !uncertain["permitrootlogin"] {
		s.RootLogin = &v
	} else if !ok && !blind {
		d := "prohibit-password" // OpenSSH's default
		s.RootLogin = &d
	}
	return s
}

// Containers are the running docker containers, from their cgroups (short ids).
func (e Env) Containers() []string {
	out := []string{}
	for _, g := range collect.Cgroups(e.Cgroup) {
		if strings.HasPrefix(g.Name, "docker-") {
			out = append(out, strings.TrimPrefix(g.Name, "docker-"))
		}
	}
	sort.Strings(out)
	return out
}

// SSHHostKeys are the public host keys, "type base64" without the comment,
// for the known_hosts of whoever connects over SSH.
func (e Env) SSHHostKeys() []string {
	files, _ := filepath.Glob(e.path("etc/ssh/ssh_host_*_key.pub"))
	sort.Strings(files)
	keys := []string{}
	for _, f := range files {
		l := strings.Fields(firstLine(f))
		if len(l) >= 2 {
			keys = append(keys, l[0]+" "+l[1])
		}
	}
	return keys
}

// Host facts that change rarely.
func (e Env) memoryBytes() int64 {
	return int64(collect.MemInfo(e.Proc)["MemTotal"]) * 1024
}

func (e Env) cpuCores() int {
	n := 0
	for _, l := range collect.ReadLines(filepath.Join(e.Proc, "stat")) {
		if strings.HasPrefix(l, "cpu") && len(l) > 3 && l[3] >= '0' && l[3] <= '9' {
			n++
		}
	}
	if n == 0 {
		n = runtime.NumCPU()
	}
	return n
}

// BootTime is when the host booted, from btime in /proc/stat.
func (e Env) BootTime() time.Time {
	for _, l := range collect.ReadLines(filepath.Join(e.Proc, "stat")) {
		if strings.HasPrefix(l, "btime ") {
			n, _ := strconv.ParseInt(strings.TrimSpace(l[6:]), 10, 64)
			return time.Unix(n, 0).UTC()
		}
	}
	return time.Time{}
}

func (e Env) diskBytes() int64 {
	var total int64
	for _, m := range collect.Mounts(e.Proc) {
		if s, err := e.Statfs(m.Point); err == nil {
			total += int64(s.Blocks * s.Bsize)
		}
	}
	return total
}

// Arch is the Debian name of the machine's architecture.
func Arch() string { return runtime.GOARCH }

// Host is the report's host object.
type Host struct {
	Hostname    string   `json:"hostname"`
	OS          string   `json:"os"`
	Kernel      string   `json:"kernel"`
	Arch        string   `json:"arch"`
	CPUCores    int      `json:"cpu_cores"`
	MemoryBytes int64    `json:"memory_bytes"`
	BootTime    string   `json:"boot_time"`
	SSHHostKeys []string `json:"ssh_host_keys"`
}

// HostFacts are what every regular report carries.
func (e Env) HostFacts() Host {
	return Host{Hostname: e.Hostname(), OS: e.OSRelease(), Kernel: e.RunningKernel(), Arch: Arch(),
		CPUCores: e.cpuCores(), MemoryBytes: e.memoryBytes(), BootTime: fmtTime(e.BootTime()), SSHHostKeys: e.SSHHostKeys()}
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// Full is everything the inventory gathers in one pass.
type Full struct {
	Summary  Summary
	Packages []Package
	Updates  Updates
	Kernel   Kernel
	Ports    []Port
	SSH      SSH
	Errors   []string
	// PackagesErr is why dpkg's status file could not be read, if it could not.
	PackagesErr error
}

// Collect gathers the inventory. withUpdates runs apt's simulation, which
// takes a second or two; without it the update counts are null.
func (e Env) Collect(ctx context.Context, version string, withUpdates bool) Full {
	var f Full
	pkgs, err := e.Packages()
	if err != nil {
		f.Errors = append(f.Errors, "packages: "+err.Error())
		f.PackagesErr = err
	}
	f.Packages = pkgs
	f.Kernel = e.Kernel(pkgs)
	f.Ports = e.Ports()
	f.SSH = e.SSHD()
	failed, err := e.FailedUnits(ctx)
	if err != nil {
		f.Errors = append(f.Errors, err.Error())
	}
	reboot, rebootPkgs := e.Reboot()
	h := e.HostFacts()
	n, sum := PackagesDigest(pkgs)
	s := Summary{
		Hostname: h.Hostname, OS: h.OS, Kernel: h.Kernel, KernelNewest: f.Kernel.Newest, Arch: h.Arch,
		CPUCores: h.CPUCores, MemoryBytes: h.MemoryBytes, DiskBytes: e.diskBytes(), BootTime: h.BootTime,
		RebootRequired: reboot, RebootPackages: rebootPkgs, PackagesCount: n, PackagesSHA256: sum,
		UnattendedUpgrades: e.UnattendedUpgrades(pkgs), FailedUnits: failed, Listening: Listening(f.Ports),
		LoginUsers: e.LoginUsers(), SSH: SSHState{Port: f.SSH.Port, PasswordAuth: f.SSH.PasswordAuth, RootLogin: f.SSH.RootLogin},
		ContainersCount: len(e.Containers()), AgentVersion: version, SSHHostKeys: h.SSHHostKeys,
	}
	if withUpdates {
		f.Updates = e.Updates(ctx)
		if f.Updates.Error == "" {
			c, sec := f.Updates.Count, f.Updates.Security
			s.UpdatesCount, s.SecurityUpdatesCount = &c, &sec
		} else {
			f.Errors = append(f.Errors, f.Updates.Error)
		}
	}
	f.Summary = s
	return f
}
