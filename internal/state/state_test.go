package state

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tetrixdev/engram-agent/internal/inventory"
)

func sp(s string) *string { return &s }

func TestSHA256IsCanonical(t *testing.T) {
	a := Section{Name: "x", Items: []json.RawMessage{json.RawMessage(`{"b":1,"a":"<x>"}`)}, Meta: json.RawMessage(`{"z":true,"y":null}`)}
	b := Section{Name: "x", CollectedAt: time.Now(), Items: []json.RawMessage{json.RawMessage(`{ "a" : "<x>", "b" : 1 }`)}, Meta: json.RawMessage(`{"y":null,"z":true}`)}
	if a.SHA256() != b.SHA256() {
		t.Fatal("the same content in another key order or spacing hashes differently")
	}
	c := b
	c.Error = sp("boom")
	if c.SHA256() == b.SHA256() {
		t.Fatal("the error is not part of the hash")
	}
	got, _ := Canonical(map[string]any{"items": a.items(), "meta": a.meta(), "error": a.Error})
	if string(got) != `{"error":null,"items":[{"a":"<x>","b":1}],"meta":{"y":null,"z":true}}` {
		t.Fatalf("canonical %s", got)
	}
	// No items and no meta are [] and {}, not null.
	e := Section{Name: "y"}
	got, _ = Canonical(map[string]any{"items": e.items(), "meta": e.meta(), "error": e.Error})
	if string(got) != `{"error":null,"items":[],"meta":{}}` {
		t.Fatalf("empty %s", got)
	}
}

func bigPackages(n int) Section {
	var pkgs []inventory.Package
	for i := 0; i < n; i++ {
		pkgs = append(pkgs, inventory.Package{Name: fmt.Sprintf("lib-package-number-%05d", i), Version: "1.2.3-4ubuntu0.24.04.1",
			Source: fmt.Sprintf("package-source-%05d (1.2.3-4ubuntu0.24.04.1)", i), Arch: "amd64"})
	}
	return Packages(pkgs, map[string]bool{}, time.Date(2026, 10, 23, 19, 0, 0, 0, time.UTC), nil)
}

func TestEventsChunking(t *testing.T) {
	sec := bigPackages(1200) // about 130 KB of items
	sec.Meta = json.RawMessage(`{"note":"first part only"}`)
	evs := sec.Events(1792000000)
	if len(evs) != 3 {
		t.Fatalf("%d parts", len(evs))
	}
	sum := sec.SHA256()
	total := 0
	for i, ev := range evs {
		b, _ := json.Marshal(ev.State)
		if len(b) >= MaxPartBytes {
			t.Errorf("part %d is %d bytes", i+1, len(b))
		}
		if ev.Ref != fmt.Sprintf("state:packages:%d", i+1) || ev.State.Part != i+1 || ev.State.Parts != 3 || ev.State.SHA256 != sum {
			t.Errorf("part %d: %s %+v", i+1, ev.Ref, ev.State.Part)
		}
		if ev.Key != fmt.Sprintf("state:packages:%d:%s:1792000000", i+1, sum[:16]) {
			t.Errorf("key %s", ev.Key)
		}
		if (i == 0) != (string(ev.State.Meta) != "{}") {
			t.Errorf("part %d meta %s", i+1, ev.State.Meta)
		}
		if ev.State.CollectedAt != "2026-10-23T19:00:00Z" {
			t.Errorf("collected_at %s", ev.State.CollectedAt)
		}
		total += len(ev.State.Items)
		// Exactly the declared keys.
		var m map[string]any
		json.Unmarshal(b, &m)
		var keys []string
		for k := range m {
			keys = append(keys, k)
		}
		if len(keys) != 8 {
			t.Errorf("state keys %v", keys)
		}
		for _, k := range []string{"section", "collected_at", "sha256", "part", "parts", "items", "meta", "error"} {
			if _, ok := m[k]; !ok {
				t.Errorf("state lacks %s", k)
			}
		}
	}
	if total != 1200 {
		t.Fatalf("%d items across the parts", total)
	}
	// One small package list is still part 1 of 1, with the :<i> ref.
	small := bigPackages(3).Events(1)
	if len(small) != 1 || small[0].Ref != "state:packages:1" || small[0].State.Parts != 1 {
		t.Fatalf("small %+v", small)
	}
	// Any other section is one event with the plain ref.
	ev := Section{Name: "users", Items: []json.RawMessage{json.RawMessage(`{}`)}}.Events(1)
	if len(ev) != 1 || ev[0].Ref != "state:users" || !strings.HasPrefix(ev[0].Key, "state:users:1:") {
		t.Fatalf("users %+v", ev)
	}
	// An empty section is one part with no items.
	ev = Section{Name: "ssh_keys"}.Events(1)
	if b, _ := json.Marshal(ev[0].State); !strings.Contains(string(b), `"items":[]`) || !strings.Contains(string(b), `"meta":{}`) {
		t.Fatalf("empty %s", b)
	}
}

func TestScopes(t *testing.T) {
	cases := map[string]string{
		"203.0.113.10": "public", "2a01:4f9:c014:e15b::1": "public",
		"10.0.0.5": "private", "172.18.0.1": "private", "192.168.1.2": "private", "fd00::1": "private",
		"100.101.1.2": "tailnet", "fd7a:115c:a1e0::1": "tailnet",
		"169.254.1.1": "link_local", "fe80::1": "link_local",
		"127.0.0.1": "loopback", "::1": "loopback",
	}
	for a, want := range cases {
		if got := Scope(net.ParseIP(a)); got != want {
			t.Errorf("Scope(%s) = %s, want %s", a, got, want)
		}
	}
	ports := map[string]string{
		"0.0.0.0":                       "public",
		"::":                            "public",
		"127.0.0.1 203.0.113.10":        "public",
		"100.101.1.2":                   "tailnet",
		"100.101.1.2 fd7a:115c:a1e0::1": "tailnet",
		"127.0.0.1 ::1":                 "loopback",
		"127.0.0.1 100.101.1.2":         "private",
		"10.0.0.5":                      "private",
		"172.17.0.1 100.101.1.2":        "private",
	}
	for in, want := range ports {
		if got := PortScope(strings.Fields(in)); got != want {
			t.Errorf("PortScope(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestPortsAndNetwork(t *testing.T) {
	at := time.Now()
	ports := []inventory.Port{
		{Proto: "tcp", Port: 22, Address: "0.0.0.0"}, {Proto: "tcp", Port: 22, Address: "::"},
		{Proto: "tcp", Port: 5432, Address: "127.0.0.1"},
		{Proto: "tcp", Port: 8080, Address: "100.101.1.2"},
		{Proto: "udp", Port: 41641, Address: "0.0.0.0"}, // inside the ephemeral range: left out
		{Proto: "udp", Port: 53, Address: "127.0.0.53"},
	}
	sec := Ports(ports, 32768, 60999, at)
	var got []Port
	for _, it := range sec.Items {
		var p Port
		json.Unmarshal(it, &p)
		got = append(got, p)
	}
	want := []Port{
		{Proto: "tcp", Port: 22, Addresses: []string{"0.0.0.0", "::"}, Scope: "public"},
		{Proto: "tcp", Port: 5432, Addresses: []string{"127.0.0.1"}, Scope: "loopback"},
		{Proto: "tcp", Port: 8080, Addresses: []string{"100.101.1.2"}, Scope: "tailnet"},
		{Proto: "udp", Port: 53, Addresses: []string{"127.0.0.53"}, Scope: "loopback"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ports %+v", got)
	}
	ifs := []Iface{
		{Name: "lo", Loopback: true, Addrs: []net.IP{net.ParseIP("127.0.0.1")}},
		{Name: "eth0", Addrs: []net.IP{net.ParseIP("203.0.113.10"), net.ParseIP("fe80::1")}},
		{Name: "tailscale0", Addrs: []net.IP{net.ParseIP("100.101.1.2")}},
		{Name: "vethabc", Addrs: []net.IP{net.ParseIP("fe80::2")}},
		{Name: "docker0", Addrs: []net.IP{net.ParseIP("172.17.0.1")}},
	}
	_, addrs := Network(ifs, at, nil)
	wantA := []Addr{
		{"docker0", "172.17.0.1", "v4", "private"},
		{"eth0", "203.0.113.10", "v4", "public"}, {"eth0", "fe80::1", "v6", "link_local"},
		{"tailscale0", "100.101.1.2", "v4", "tailnet"},
	}
	if !reflect.DeepEqual(addrs, wantA) {
		t.Fatalf("network %+v", addrs)
	}
}

func TestPackagesManual(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "extended_states")
	os.WriteFile(p, []byte("Package: libfoo1\nArchitecture: amd64\nAuto-Installed: 1\n\nPackage: nginx\nArchitecture: amd64\nAuto-Installed: 0\n\nPackage: libbar\nAuto-Installed: 1\n"), 0o644)
	auto, err := ReadAutoInstalled(p)
	if err != nil {
		t.Fatal(err)
	}
	sec := Packages([]inventory.Package{
		{Name: "libbar", Version: "1", Source: "bar", Arch: "all"},
		{Name: "libfoo1", Version: "2.0-1", Source: "foo (2.0-1build1)", Arch: "amd64"},
		{Name: "libfoo1", Version: "2.0-1", Source: "foo (2.0-1build1)", Arch: "i386"},
		{Name: "nginx", Version: "1.24", Source: "nginx", Arch: "amd64"},
	}, auto, time.Now(), nil)
	var got []string
	for _, it := range sec.Items {
		got = append(got, string(it))
	}
	want := []string{`["libbar","1","bar","all",false]`, `["libfoo1","2.0-1","foo (2.0-1build1)","amd64",false]`,
		`["libfoo1","2.0-1","foo (2.0-1build1)","i386",true]`, `["nginx","1.24","nginx","amd64",true]`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("items %v", got)
	}
	if a, err := ReadAutoInstalled(filepath.Join(dir, "none")); err != nil || len(a) != 0 {
		t.Fatal("a missing extended_states")
	}
}

// TestPackagesManualArchAll: apt records an Architecture: all package in
// extended_states under the native architecture (amd64), as apt's cache
// gives arch-all packages the native one. The fixture is real dpkg status and
// extended_states stanzas from an Ubuntu 24.04 amd64 host where
// `apt-mark showmanual` lists pandoc and libreoffice-common, and not
// pandoc-data or fonts-dejavu-core.
func TestPackagesManualArchAll(t *testing.T) {
	root := filepath.Join("testdata", "apt-arch-all")
	pkgs, err := inventory.ReadDpkgStatus(filepath.Join(root, "var/lib/dpkg/status"))
	if err != nil {
		t.Fatal(err)
	}
	auto, err := ReadAutoInstalled(filepath.Join(root, "var/lib/apt/extended_states"))
	if err != nil {
		t.Fatal(err)
	}
	manual := map[string]bool{}
	for _, it := range Packages(pkgs, auto, time.Now(), nil).Items {
		var row []any
		if err := json.Unmarshal(it, &row); err != nil {
			t.Fatal(err)
		}
		manual[row[0].(string)+":"+row[3].(string)] = row[4].(bool)
	}
	want := map[string]bool{"dpkg:amd64": true, "pandoc:amd64": true, "libreoffice-common:all": true,
		"pandoc-data:all": false, "fonts-dejavu-core:all": false}
	if !reflect.DeepEqual(manual, want) {
		t.Fatalf("manual %v, want %v", manual, want)
	}

	// The native architecture is dpkg's own, not the agent binary's: on an
	// arm64 host an arch-all package is under arm64, and an amd64 entry is a
	// foreign one that does not apply.
	pkgs = []inventory.Package{{Name: "dpkg", Version: "1", Source: "dpkg", Arch: "arm64"},
		{Name: "fonts-dejavu-core", Version: "2.37-8", Source: "fonts-dejavu", Arch: "all"},
		{Name: "pandoc-data", Version: "3.1.3-1", Source: "haskell-pandoc", Arch: "all"}}
	auto = map[string]bool{"fonts-dejavu-core:arm64": true, "pandoc-data:amd64": true}
	var got []string
	for _, it := range Packages(pkgs, auto, time.Now(), nil).Items {
		got = append(got, string(it))
	}
	wantArm := []string{`["dpkg","1","dpkg","arm64",true]`, `["fonts-dejavu-core","2.37-8","fonts-dejavu","all",false]`,
		`["pandoc-data","3.1.3-1","haskell-pandoc","all",true]`}
	if !reflect.DeepEqual(got, wantArm) {
		t.Fatalf("arm64 items %v", got)
	}
}

func TestReadSnapshot(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state.json")
	now := time.Date(2026, 10, 23, 19, 10, 0, 0, time.UTC)
	if s := ReadSnapshot(p, now); s.Status != SnapshotMissing {
		t.Fatalf("missing: %+v", s)
	}
	os.WriteFile(p, []byte("{not json"), 0o640)
	if s := ReadSnapshot(p, now); s.Status != SnapshotUnreadable || s.Err == nil {
		t.Fatalf("broken: %+v", s)
	}
	doc := `{"version":1,"collected_at":"2026-10-23T19:00:00Z","agent_version":"0.2.0","sections":{
	 "firewall":{"items":[{"family":"v4","chain":"INPUT","rule":"-j ACCEPT","comment":null,"target":"ACCEPT"}],"meta":{"backend":"nf_tables"},"error":null},
	 "containers":{"items":[],"meta":{"docker":false},"error":null},
	 "users":{"items":[],"meta":{},"error":"/etc/group: denied"},
	 "tailscale":{"items":[],"meta":{"installed":false},"error":null}}}`
	os.WriteFile(p, []byte(doc), 0o640)
	s := ReadSnapshot(p, now)
	if s.Status != SnapshotOK || len(s.Sections) != 5 {
		t.Fatalf("ok: %+v", s)
	}
	fw, _ := s.Find("firewall")
	if len(fw.Items) != 1 || !fw.CollectedAt.Equal(time.Date(2026, 10, 23, 19, 0, 0, 0, time.UTC)) {
		t.Fatalf("firewall %+v", fw)
	}
	if u, _ := s.Find("users"); u.Error == nil || *u.Error != "/etc/group: denied" {
		t.Fatalf("users error %+v", u)
	}
	if k, _ := s.Find("ssh_keys"); k.Error == nil {
		t.Fatal("a section missing from the file is not an error")
	}
	sec := s.Section(now)
	if string(sec.Meta) != `{"collected_at":"2026-10-23T19:00:00Z","error":null,"status":"ok"}` || len(sec.Items) != 0 {
		t.Fatalf("snapshot section %s", sec.Meta)
	}
	if s := ReadSnapshot(p, now.Add(31*time.Minute)); s.Status != SnapshotStale || len(s.Sections) != 0 {
		t.Fatalf("stale: %+v", s)
	}
	os.Chmod(p, 0)
	if os.Getuid() != 0 {
		if s := ReadSnapshot(p, now); s.Status != SnapshotUnreadable {
			t.Fatalf("no permission: %+v", s)
		}
	}
}

func TestUncommented(t *testing.T) {
	rule := func(fam, chain, r string, comment, target *string) json.RawMessage {
		b, _ := json.Marshal(FirewallRule{Family: fam, Chain: chain, Rule: r, Comment: comment, Target: target})
		return b
	}
	items := []json.RawMessage{
		rule("v4", "INPUT", "-j ts-input", nil, sp("ts-input")),                                                           // a jump into Tailscale's chain
		rule("v4", "FORWARD", "-j DOCKER-USER", nil, sp("DOCKER-USER")),                                                   // into Docker's
		rule("v4", "INPUT", "-p tcp --dport 443 -j ACCEPT", sp("web: proxy serves the sites; 80 for ACME"), sp("ACCEPT")), // a reason
		rule("v4", "INPUT", "-p tcp --dport 22 -j ACCEPT", nil, sp("ACCEPT")),                                             // no comment
		rule("v6", "INPUT", "-p tcp --dport 9000 -j ACCEPT", sp("todo"), sp("ACCEPT")),                                    // not a reason
		rule("v4", "INPUT", "-p tcp --dport 9001 -j ACCEPT", sp("Web: Upper case key is not a key here"), sp("ACCEPT")),
		rule("v4", "INPUT", "-p tcp --dport 9002 -j ACCEPT", sp("web: too short"), sp("ACCEPT")),
		rule("v4", "OUTPUT", "-d 10.0.0.0/8 -j DROP", nil, sp("DROP")),
		rule("v4", "DOCKER-USER", "-i tailscale0 -j RETURN", nil, sp("RETURN")),
		rule("v4", "DOCKER-USER", "-j DROP", sp("docker: drop what the host rules above did not let through"), sp("DROP")),
		rule("v4", "DOCKER", "! -i docker0 -o docker0 -j DROP", nil, sp("DROP")), // Docker's own chain: not judged
		rule("v4", "ts-input", "-i lo -j ACCEPT", nil, sp("ACCEPT")),             // Tailscale's: not judged
		rule("v4", "INPUT", "-p icmp", nil, nil),                                 // no target is judged too
	}
	got := Uncommented(items)
	var names []string
	for _, r := range got {
		names = append(names, r.Family+" "+r.Chain+" "+r.Rule)
	}
	want := []string{"v4 INPUT -p tcp --dport 22 -j ACCEPT", "v6 INPUT -p tcp --dport 9000 -j ACCEPT", "v4 INPUT -p tcp --dport 9001 -j ACCEPT",
		"v4 INPUT -p tcp --dport 9002 -j ACCEPT", "v4 OUTPUT -d 10.0.0.0/8 -j DROP", "v4 DOCKER-USER -i tailscale0 -j RETURN", "v4 INPUT -p icmp"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("uncommented\n%q\nwant\n%q", names, want)
	}
	f := FirewallFindings(got)
	if len(f) != 7 {
		t.Fatalf("%d findings", len(f))
	}
	k := "firewall_uncommented:v4:INPUT:"
	for key, fd := range f {
		if strings.HasPrefix(key, k) && *fd.Subject == "-p tcp --dport 22 -j ACCEPT" {
			if fd.Kind != "firewall_rule_uncommented" || fd.Severity != "high" || fd.Category != "security" ||
				fd.Title != "Firewall rule without a reason: INPUT -p tcp --dport 22 -j ACCEPT" || !strings.Contains(*fd.Detail, `-m comment --comment "<key>: <why, 20+ characters>"`) {
				t.Errorf("finding %+v", fd)
			}
			if len(strings.TrimPrefix(key, k)) != 12 {
				t.Errorf("key %s", key)
			}
		}
	}
	long := FirewallFindings([]FirewallRule{{Family: "v4", Chain: "INPUT", Rule: strings.Repeat("-s 10.0.0.1 ", 40)}})
	for _, fd := range long {
		if n := len([]rune(fd.Title)); n > 200 {
			t.Errorf("title of %d characters", n)
		}
	}
}
