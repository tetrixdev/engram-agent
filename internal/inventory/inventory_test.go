package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tetrixdev/engram/agent/internal/collect"
)

func write(t *testing.T, root, rel, content string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// fixtureEnv is a whole fake server: /etc, /var, /proc and a cgroup tree.
func fixtureEnv(t *testing.T) Env {
	root := t.TempDir()
	w := func(rel, content string) { write(t, root, rel, content, 0o644) }
	w("etc/os-release", "NAME=\"Ubuntu\"\nVERSION=\"24.04.1 LTS (Noble Numbat)\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nID=ubuntu\n")
	w("var/lib/dpkg/status", fixture(t, "dpkg-status"))
	w("var/run/reboot-required", "*** System restart required ***\n")
	w("var/run/reboot-required.pkgs", "linux-image-6.8.0-147-generic\nlibc6\nlinux-image-6.8.0-147-generic\n")
	w("etc/apt/apt.conf.d/20auto-upgrades", "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n")
	w("etc/passwd", "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ndeploy:x:1000:1000::/home/deploy:/bin/bash\nengram-agent:x:999:999::/var/lib/engram-agent:/usr/sbin/nologin\nsvc:x:998:998::/srv:/bin/false\n")
	w("etc/ssh/sshd_config", "# defaults\nInclude /etc/ssh/sshd_config.d/*.conf\nPort 22\nPermitRootLogin no\nPasswordAuthentication no\nMatch User backup\n  PasswordAuthentication yes\n")
	w("etc/ssh/sshd_config.d/10-local.conf", "PermitRootLogin prohibit-password\n")
	w("etc/ssh/ssh_host_ed25519_key.pub", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample root@web01\n")
	w("etc/ssh/ssh_host_rsa_key.pub", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQExample root@web01\n")
	w("proc/sys/kernel/hostname", "web01\n")
	w("proc/sys/kernel/osrelease", "6.8.0-138-generic\n")
	w("proc/sys/net/ipv4/ip_local_port_range", "32768\t60999\n")
	w("proc/stat", "cpu  1 1 1 1 1 1 1 1 0 0\ncpu0 1 1 1 1 1 1 1 1 0 0\ncpu1 1 1 1 1 1 1 1 1 0 0\nbtime 1790000000\n")
	w("proc/meminfo", "MemTotal:       16384000 kB\nMemAvailable:    8000000 kB\n")
	w("proc/self/mountinfo", "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n27 22 8:2 / /var rw - xfs /dev/sda2 rw\n")
	w("proc/net/tcp", fixture(t, "proc-net-tcp"))
	w("proc/net/tcp6", fixture(t, "proc-net-tcp6"))
	w("proc/net/udp", fixture(t, "proc-net-udp"))
	if err := os.MkdirAll(filepath.Join(root, "cgroup/system.slice/docker-0123456789abcdef0123.scope"), 0o755); err != nil {
		t.Fatal(err)
	}
	apt := fixture(t, "apt-simulate.txt")
	return Env{
		Root: root, Proc: filepath.Join(root, "proc"), Cgroup: filepath.Join(root, "cgroup"),
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			switch name {
			case "systemctl":
				return []byte("nginx.service  loaded failed failed A high performance web server\nbackup.timer loaded failed failed Nightly backup\n"), nil
			case "apt-get":
				if strings.Join(args, " ") != "-s -q -o Debug::NoLocking=true dist-upgrade" {
					return nil, errors.New("unexpected apt-get " + strings.Join(args, " "))
				}
				return []byte("NOTE: This is only a simulation!\n" + apt), nil
			}
			return nil, errors.New("unexpected command " + name)
		},
		Statfs: func(path string) (collect.FsStat, error) {
			return collect.FsStat{Blocks: 1000, Bsize: 4096}, nil
		},
	}
}

func TestSummaryFromFixtures(t *testing.T) {
	e := fixtureEnv(t)
	// apt-get is looked for under the fixture root.
	write(t, e.Root, "usr/bin/apt-get", "", 0o755)
	f := e.Collect(context.Background(), "0.2.0", true)
	if len(f.Errors) != 0 {
		t.Fatalf("errors: %v", f.Errors)
	}
	s := f.Summary
	b, _ := json.Marshal(s)
	var keys map[string]any
	_ = json.Unmarshal(b, &keys)
	want := []string{"hostname", "os", "kernel", "kernel_newest", "arch", "cpu_cores", "memory_bytes", "disk_bytes", "boot_time",
		"reboot_required", "reboot_packages", "packages_count", "packages_sha256", "updates_count", "security_updates_count",
		"unattended_upgrades", "failed_units", "listening", "login_users", "ssh", "containers_count", "agent_version", "ssh_host_keys"}
	if len(keys) != len(want) {
		t.Errorf("summary has %d keys, the Servers app declares %d: %v", len(keys), len(want), keys)
	}
	for _, k := range want {
		if _, ok := keys[k]; !ok {
			t.Errorf("summary lacks %s", k)
		}
	}
	check := func(name string, got, want any) {
		t.Helper()
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %#v, want %#v", name, got, want)
		}
	}
	check("hostname", s.Hostname, "web01")
	check("os", s.OS, "Ubuntu 24.04.1 LTS")
	check("kernel", s.Kernel, "6.8.0-138-generic")
	check("kernel_newest", *s.KernelNewest, "6.8.0-147-generic")
	check("cpu_cores", s.CPUCores, 2)
	check("memory_bytes", s.MemoryBytes, int64(16384000*1024))
	check("disk_bytes", s.DiskBytes, int64(2*1000*4096))
	check("boot_time", s.BootTime, "2026-09-21T14:13:20Z")
	check("reboot", s.RebootRequired, true)
	check("reboot_packages", s.RebootPackages, []string{"libc6", "linux-image-6.8.0-147-generic"})
	check("packages_count", s.PackagesCount, 7) // linux-image-6.8.0-139 is only config files
	check("updates", *s.UpdatesCount, 7)
	check("security", *s.SecurityUpdatesCount, 1)
	check("unattended", *s.UnattendedUpgrades, true)
	check("failed", s.FailedUnits, []string{"backup.timer", "nginx.service"})
	check("listening", s.Listening, []string{"tcp/22", "tcp/80", "tcp/40000", "udp/68"})
	check("users", s.LoginUsers, []string{"deploy", "root"})
	check("ssh port", s.SSH.Port, 22)
	check("ssh password", *s.SSH.PasswordAuth, false)
	check("ssh root (the drop-in comes first and wins)", *s.SSH.RootLogin, "prohibit-password")
	check("containers", s.ContainersCount, 1)
	check("host keys", s.SSHHostKeys, []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQExample"})
	check("agent_version", s.AgentVersion, "0.2.0")
	if len(b) > 64<<10 {
		t.Errorf("summary is %d bytes", len(b))
	}
	// The ports section keeps the loopback ones, with addresses.
	var local []string
	for _, p := range f.Ports {
		if p.Local {
			local = append(local, p.Proto+" "+p.Address)
		}
	}
	check("loopback ports", local, []string{"tcp 127.0.0.1", "tcp ::1", "udp 127.0.0.53"})
	// The digest changes with the list and only with it.
	_, again := PackagesDigest(f.Packages)
	check("digest stable", again, s.PackagesSHA256)
	f.Packages[0].Version = "9"
	if _, changed := PackagesDigest(f.Packages); changed == s.PackagesSHA256 {
		t.Error("digest did not change with a version")
	}
}

func TestPackagesParsing(t *testing.T) {
	e := fixtureEnv(t)
	p, err := e.Packages()
	if err != nil {
		t.Fatal(err)
	}
	var ssh Package
	for _, x := range p {
		if x.Name == "openssh-server" {
			ssh = x
		}
		if x.Name == "not-a-package" || x.Name == "linux-image-6.8.0-139-generic" {
			t.Errorf("listed %s", x.Name)
		}
	}
	if ssh.Version != "1:9.6p1-3ubuntu13.5" || ssh.Source != "openssh (1:9.6p1-3ubuntu13.5)" || ssh.Arch != "amd64" {
		t.Fatalf("openssh-server %+v", ssh)
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.1", -1},
		{"1:1.0", "2.0", 1},
		{"1.0~rc1", "1.0", -1},
		{"1.0-1", "1.0-2", -1},
		{"6.8.0-147.147", "6.8.0-138.138", 1},
		{"6.8.0-99.99", "6.8.0-100.100", -1},
		{"2.39-0ubuntu8.9", "2.39-0ubuntu8.10", -1},
		{"1.0a", "1.0", 1},
		{"1.0+b1", "1.0", 1},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); (got > 0) != (c.want > 0) || (got < 0) != (c.want < 0) {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestSSHDUnreadableAndDefaults(t *testing.T) {
	e := fixtureEnv(t)
	// Nothing set anywhere: OpenSSH's defaults.
	write(t, e.Root, "etc/ssh/sshd_config", "Port 2222\nPort 2223\n", 0o644)
	if err := os.Remove(filepath.Join(e.Root, "etc/ssh/sshd_config.d/10-local.conf")); err != nil {
		t.Fatal(err)
	}
	s := e.SSHD()
	if s.Port != 2222 || len(s.Ports) != 2 || !*s.PasswordAuth || *s.RootLogin != "prohibit-password" {
		t.Fatalf("defaults %+v", s)
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads every file")
	}
	// A drop-in this user cannot read comes before the main file's line: unknown.
	write(t, e.Root, "etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\n", 0o644)
	write(t, e.Root, "etc/ssh/sshd_config.d/50-cloud-init.conf", "PasswordAuthentication yes\n", 0o600)
	os.Chmod(filepath.Join(e.Root, "etc/ssh/sshd_config.d/50-cloud-init.conf"), 0)
	s = e.SSHD()
	if s.PasswordAuth != nil || s.RootLogin != nil || len(s.Unreadable) != 1 {
		t.Fatalf("unreadable drop-in: %+v", s)
	}
}

func TestFindings(t *testing.T) {
	e := fixtureEnv(t)
	s := e.Collect(context.Background(), "0.2.0", false).Summary
	yes := true
	s.SSH.PasswordAuth = &yes
	baseline := map[string]bool{"tcp/22": true, "udp/68": true}
	got := Findings(s, baseline, 32768, 60999)
	want := []string{"failed_unit:backup.timer", "failed_unit:nginx.service", "kernel_not_running_newest",
		"new_port:tcp/80", "pending_reboot", "ssh_password_auth", "ssh_root_login"}
	if k := Keys(got); !reflect.DeepEqual(k, want) {
		t.Fatalf("findings %v, want %v", k, want)
	}
	if f := got["ssh_root_login"]; f.Severity != "low" || f.Category != "security" {
		t.Errorf("key-only root login: %+v", f)
	}
	if f := got["new_port:tcp/80"]; *f.Subject != "tcp/80" || f.Kind != "new_port" {
		t.Errorf("new port %+v", f)
	}
	if f := got["failed_unit:nginx.service"]; *f.Subject != "nginx.service" || f.Category != "maintenance" {
		t.Errorf("failed unit %+v", f)
	}
	// Without a baseline (not enrolled yet) no port is new.
	if _, ok := Findings(s, nil, 32768, 60999)["new_port:tcp/80"]; ok {
		t.Error("new port without a baseline")
	}
	// The fields are exactly the declared state keys.
	b, _ := json.Marshal(got["pending_reboot"])
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	for _, k := range []string{"kind", "category", "severity", "title", "detail", "since", "subject"} {
		if _, ok := m[k]; !ok {
			t.Errorf("finding lacks %s", k)
		}
	}
	if len(m) != 7 {
		t.Errorf("finding keys %v", m)
	}
}

func TestParseFailedUnits(t *testing.T) {
	got := ParseFailedUnits("● nginx.service loaded failed failed nginx\n  x.mount loaded failed failed X\n\n")
	if !reflect.DeepEqual(got, []string{"nginx.service", "x.mount"}) {
		t.Fatal(got)
	}
}
