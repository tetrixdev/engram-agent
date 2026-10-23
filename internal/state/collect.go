package state

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tetrixdev/engram-agent/internal/inventory"
)

// ReadAutoInstalled reads apt's /var/lib/apt/extended_states: the packages
// marked Auto-Installed: 1, as "name:arch" (and "name" when a stanza names
// no architecture). A missing file marks nothing.
func ReadAutoInstalled(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return map[string]bool{}, nil
		}
		return map[string]bool{}, err
	}
	defer f.Close()
	auto := map[string]bool{}
	var name, arch string
	var isAuto bool
	flush := func() {
		if name != "" && isAuto {
			if arch != "" {
				auto[name+":"+arch] = true
			} else {
				auto[name] = true
			}
		}
		name, arch, isAuto = "", "", false
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		l := sc.Text()
		if strings.TrimSpace(l) == "" {
			flush()
			continue
		}
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Package":
			name = v
		case "Architecture":
			arch = v
		case "Auto-Installed":
			isAuto = v == "1"
		}
	}
	flush()
	return auto, sc.Err()
}

// Packages is the packages section: [name, version, source, arch, manual]
// per installed package, sorted by name and architecture. manual is true
// unless apt marked the package automatically installed.
func Packages(pkgs []inventory.Package, auto map[string]bool, at time.Time, err error) Section {
	items := make([]json.RawMessage, 0, len(pkgs))
	for _, p := range pkgs {
		manual := !(auto[p.Name+":"+p.Arch] || auto[p.Name])
		b, _ := json.Marshal([]any{p.Name, p.Version, p.Source, p.Arch, manual})
		items = append(items, b)
	}
	return Section{Name: "packages", CollectedAt: at, Items: items, Meta: RawMeta(nil), Error: errp(err)}
}

func errp(err error) *string {
	if err == nil {
		return nil
	}
	s := err.Error()
	return &s
}

var (
	tailnetV4 = mustCIDR("100.64.0.0/10")
	tailnetV6 = mustCIDR("fd7a:115c:a1e0::/48")
	linkV4    = mustCIDR("169.254.0.0/16")
)

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// Scope says what can reach an address: loopback, tailnet (Tailscale's
// 100.64.0.0/10 and fd7a:115c:a1e0::/48), link_local, private (RFC 1918 and
// fc00::/7 other than Tailscale's) or public (any other global unicast).
func Scope(ip net.IP) string {
	switch {
	case ip == nil:
		return "private"
	case ip.IsLoopback():
		return "loopback"
	case tailnetV4.Contains(ip) || tailnetV6.Contains(ip):
		return "tailnet"
	case ip.IsLinkLocalUnicast() || linkV4.Contains(ip):
		return "link_local"
	case ip.IsPrivate():
		return "private"
	case ip.IsGlobalUnicast():
		return "public"
	}
	return "private"
}

// Addr is one address on one of the host's interfaces.
type Addr struct {
	Interface string `json:"interface"`
	Address   string `json:"address"`
	Family    string `json:"family"` // v4, v6
	Scope     string `json:"scope"`
}

// Iface is an interface and its addresses, as net.Interfaces gives them.
type Iface struct {
	Name     string
	Loopback bool
	Addrs    []net.IP
}

// HostInterfaces reads the host's interfaces (over netlink).
func HostInterfaces() ([]Iface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []Iface
	for _, i := range ifs {
		f := Iface{Name: i.Name, Loopback: i.Flags&net.FlagLoopback != 0}
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				f.Addrs = append(f.Addrs, n.IP)
			}
		}
		out = append(out, f)
	}
	return out, nil
}

// Network is the network section: every address of every interface but
// loopback and the veth half of each container (they come and go with
// containers), sorted.
func Network(ifs []Iface, at time.Time, err error) (Section, []Addr) {
	addrs := []Addr{}
	for _, i := range ifs {
		if i.Loopback || strings.HasPrefix(i.Name, "veth") {
			continue
		}
		for _, ip := range i.Addrs {
			if ip.IsLoopback() {
				continue
			}
			fam := "v6"
			if ip.To4() != nil {
				fam = "v4"
			}
			addrs = append(addrs, Addr{Interface: i.Name, Address: ip.String(), Family: fam, Scope: Scope(ip)})
		}
	}
	sort.Slice(addrs, func(i, j int) bool {
		if addrs[i].Interface != addrs[j].Interface {
			return addrs[i].Interface < addrs[j].Interface
		}
		return addrs[i].Address < addrs[j].Address
	})
	return Section{Name: "network", CollectedAt: at, Items: Raw(addrs), Meta: RawMeta(nil), Error: errp(err)}, addrs
}

// Port is one listening port with every address it listens on.
type Port struct {
	Proto     string   `json:"proto"`
	Port      int      `json:"port"`
	Addresses []string `json:"addresses"`
	Scope     string   `json:"scope"` // public, tailnet, loopback, private
}

// PortScope judges who can reach a port from the addresses it listens on:
// public when any is unspecified (0.0.0.0, ::) or a public address; else
// tailnet when every one is a tailnet address; loopback when every one is a
// loopback address; else private.
func PortScope(addresses []string) string {
	allTail, allLoop := len(addresses) > 0, len(addresses) > 0
	for _, a := range addresses {
		ip := net.ParseIP(a)
		if ip == nil {
			allTail, allLoop = false, false
			continue
		}
		if ip.IsUnspecified() {
			return "public"
		}
		sc := Scope(ip)
		if sc == "public" {
			return "public"
		}
		allTail = allTail && sc == "tailnet"
		allLoop = allLoop && sc == "loopback"
	}
	switch {
	case allTail:
		return "tailnet"
	case allLoop:
		return "loopback"
	}
	return "private"
}

// Ports is the ports section: the listening sockets grouped by protocol and
// port. UDP ports inside the kernel's ephemeral range (passing sockets,
// e.g. a resolver's) are left out.
func Ports(ports []inventory.Port, ephLo, ephHi int, at time.Time) Section {
	type key struct {
		proto string
		port  int
	}
	group := map[key]map[string]bool{}
	for _, p := range ports {
		if p.Proto == "udp" && p.Port >= ephLo && p.Port <= ephHi {
			continue
		}
		k := key{p.Proto, p.Port}
		if group[k] == nil {
			group[k] = map[string]bool{}
		}
		group[k][p.Address] = true
	}
	out := make([]Port, 0, len(group))
	for k, set := range group {
		var addrs []string
		for a := range set {
			addrs = append(addrs, a)
		}
		sort.Strings(addrs)
		out = append(out, Port{Proto: k.proto, Port: k.port, Addresses: addrs, Scope: PortScope(addrs)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Proto != out[j].Proto {
			return out[i].Proto < out[j].Proto
		}
		return out[i].Port < out[j].Port
	})
	return Section{Name: "ports", CollectedAt: at, Items: Raw(out), Meta: RawMeta(nil)}
}

// Snapshot statuses.
const (
	SnapshotOK         = "ok"
	SnapshotMissing    = "missing"
	SnapshotStale      = "stale"
	SnapshotUnreadable = "unreadable"
)

// StaleAfter is how old a snapshot may be before it counts as stale.
const StaleAfter = 30 * time.Minute

// Snapshot is what the agent made of the root snapshot's file.
type Snapshot struct {
	Status      string
	CollectedAt *time.Time
	Err         *string
	Sections    []Section // the five snapshot sections; only when Status is ok
}

type rawSection struct {
	Items []json.RawMessage `json:"items"`
	Meta  json.RawMessage   `json:"meta"`
	Error *string           `json:"error"`
}

// ReadSnapshot reads the root snapshot's file and judges it.
func ReadSnapshot(path string, now time.Time) Snapshot {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Snapshot{Status: SnapshotMissing}
		}
		return Snapshot{Status: SnapshotUnreadable, Err: errp(err)}
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 16<<20))
	if err != nil {
		return Snapshot{Status: SnapshotUnreadable, Err: errp(err)}
	}
	var doc struct {
		Version     int                   `json:"version"`
		CollectedAt string                `json:"collected_at"`
		Sections    map[string]rawSection `json:"sections"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return Snapshot{Status: SnapshotUnreadable, Err: errp(fmt.Errorf("%s: %w", path, err))}
	}
	at, err := time.Parse(time.RFC3339, doc.CollectedAt)
	if err != nil {
		return Snapshot{Status: SnapshotUnreadable, Err: errp(fmt.Errorf("%s: collected_at: %w", path, err))}
	}
	if doc.Version != 1 {
		return Snapshot{Status: SnapshotUnreadable, CollectedAt: &at, Err: errp(fmt.Errorf("%s: version %d, this agent reads version 1", path, doc.Version))}
	}
	s := Snapshot{Status: SnapshotOK, CollectedAt: &at}
	if now.Sub(at) > StaleAfter {
		s.Status = SnapshotStale
		return s
	}
	for _, n := range []string{"firewall", "containers", "users", "ssh_keys", "tailscale"} {
		rs, ok := doc.Sections[n]
		sec := Section{Name: n, CollectedAt: at, Items: rs.Items, Meta: rs.Meta, Error: rs.Error}
		if !ok {
			msg := "the snapshot has no " + n + " section"
			sec.Error = &msg
		}
		s.Sections = append(s.Sections, sec)
	}
	return s
}

// Section is the snapshot section: items [], meta {status, collected_at, error}.
func (s Snapshot) Section(at time.Time) Section {
	var ca *string
	if s.CollectedAt != nil {
		v := s.CollectedAt.UTC().Format(time.RFC3339)
		ca = &v
	}
	return Section{Name: "snapshot", CollectedAt: at, Items: []json.RawMessage{},
		Meta: RawMeta(map[string]any{"status": s.Status, "collected_at": ca, "error": s.Err})}
}

// Find is the named section of the snapshot, if read.
func (s Snapshot) Find(name string) (Section, bool) {
	for _, sec := range s.Sections {
		if sec.Name == name {
			return sec, true
		}
	}
	return Section{}, false
}

// Collect builds the sections the agent itself reads (packages, network,
// ports) from an inventory pass, then the snapshot status section and, when
// the snapshot is ok, its five sections.
func Collect(full inventory.Full, root string, ephLo, ephHi int, ifaces func() ([]Iface, error), snap Snapshot, now time.Time) []Section {
	auto, aerr := ReadAutoInstalled(filepath.Join(root, "var/lib/apt/extended_states"))
	perr := full.PackagesErr
	if perr == nil && aerr != nil {
		perr = fmt.Errorf("/var/lib/apt/extended_states: %w", aerr)
	}
	out := []Section{Packages(full.Packages, auto, now, perr)}
	ifs, ierr := ifaces()
	nw, _ := Network(ifs, now, ierr)
	out = append(out, nw, Ports(full.Ports, ephLo, ephHi, now))
	if snap.Status == SnapshotOK {
		out = append(out, snap.Sections...)
	}
	return append(out, snap.Section(now))
}
