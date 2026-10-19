package collect

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fixture is a fake /proc, /sys and cgroup tree in a temp dir.
type fixture struct {
	t    *testing.T
	root string
}

func (f fixture) write(rel, content string) {
	f.t.Helper()
	p := filepath.Join(f.root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f fixture) mkdir(rel string) {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Join(f.root, rel), 0o755); err != nil {
		f.t.Fatal(err)
	}
}

const dockerID = "4f1c2a9e8b7d6c5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f"

const mountinfo = `22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
23 22 0:21 / /proc rw,nosuid shared:5 - proc proc rw
24 22 0:22 / /sys rw shared:6 - sysfs sysfs rw
25 22 0:5 / /dev rw shared:2 - devtmpfs udev rw
26 22 0:25 / /run rw shared:9 - tmpfs tmpfs rw
27 22 8:2 / /var rw,relatime shared:10 - xfs /dev/sda2 rw
28 22 8:1 /tmp/systemd-private-abc/tmp /tmp rw,relatime shared:1 - ext4 /dev/sda1 rw
29 22 7:3 / /snap/core/1 ro shared:12 - squashfs /dev/loop3 ro
30 22 0:40 / /var/lib/docker/overlay2/x/merged rw - overlay overlay rw
31 22 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw
32 22 8:3 / /mnt/my\040disk rw - ext4 /dev/sdb1 rw
33 27 8:2 /lib/docker/volumes/v /data rw - xfs /dev/sda2 rw
`

func newFixture(t *testing.T) fixture {
	f := fixture{t, t.TempDir()}
	f.write("proc/loadavg", "0.80 0.60 0.40 2/345 6789\n")
	f.write("proc/meminfo", "MemTotal:       16000000 kB\nMemFree:         2000000 kB\nMemAvailable:    6000000 kB\nBuffers:          100000 kB\nCached:          3000000 kB\nSwapTotal:       4000000 kB\nSwapFree:        3000000 kB\n")
	f.write("proc/pressure/cpu", "some avg10=1.20 avg60=0.80 avg300=0.50 total=123456\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
	f.write("proc/pressure/memory", "some avg10=0.50 avg60=0.10 avg300=0.00 total=1000\nfull avg10=0.25 avg60=0.05 avg300=0.00 total=500\n")
	f.write("proc/pressure/io", "some avg10=3.00 avg60=1.00 avg300=0.20 total=9000\nfull avg10=2.00 avg60=0.50 avg300=0.10 total=4000\n")
	f.write("proc/self/mountinfo", mountinfo)
	f.mkdir("sys/block/sda")
	f.mkdir("sys/block/nvme0n1")
	f.mkdir("sys/class/net/eth0/device")
	f.mkdir("sys/class/net/docker0")
	f.mkdir("cgroup/system.slice/docker-" + dockerID + ".scope")
	f.mkdir("cgroup/system.slice/nginx.service")
	f.mkdir("cgroup/system.slice/init.scope")
	f.mkdir("cgroup/docker/" + strings.Repeat("ab", 32))
	return f
}

// counters writes the counter files for one moment; k scales every counter.
func (f fixture) counters(k uint64) {
	// user nice system idle iowait irq softirq steal guest guest_nice
	f.write("proc/stat", fmt.Sprintf("cpu  %d %d %d %d %d %d %d %d 0 0\ncpu0 1 1 1 1 1 1 1 1 0 0\ncpu1 1 1 1 1 1 1 1 1 0 0\nintr 1\n",
		1000*k, 100*k, 500*k, 7000*k, 400*k, 50*k, 50*k, 100*k))
	f.write("proc/diskstats", fmt.Sprintf(
		"   8       0 sda %d 0 %d 0 %d 0 %d 0 0 0 0\n   8       1 sda1 5 0 %d 0 5 0 %d 0 0 0 0\n   7       0 loop0 1 0 %d 0 1 0 %d 0 0 0 0\n 259       0 nvme0n1 1 0 %d 0 1 0 %d 0 0 0 0\n",
		10*k, 2000*k, 20*k, 4000*k, 999*k, 999*k, 999*k, 999*k, 100*k, 300*k))
	f.write("proc/net/dev", fmt.Sprintf(`Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: %d 10 0 0 0 0 0 0 %d 10 0 0 0 0 0 0
  eth0: %d 100 %d 0 0 0 0 0 %d 100 %d 0 0 0 0 0
docker0: %d 50 0 0 0 0 0 0 %d 50 0 0 0 0 0 0
vethab12: %d 50 0 0 0 0 0 0 %d 50 0 0 0 0 0 0
`, 5000*k, 5000*k, 10000*k, k, 3000*k, 2*k, 800*k, 900*k, 800*k, 900*k))
	f.write("cgroup/system.slice/docker-"+dockerID+".scope/cpu.stat", fmt.Sprintf("usage_usec %d\nuser_usec 1\nsystem_usec 1\n", 2_000_000*k))
	f.write("cgroup/system.slice/docker-"+dockerID+".scope/memory.current", "104857600\n")
	f.write("cgroup/system.slice/nginx.service/cpu.stat", fmt.Sprintf("usage_usec %d\n", 500_000*k))
	f.write("cgroup/system.slice/nginx.service/memory.current", "20971520\n")
	f.write("cgroup/docker/"+strings.Repeat("ab", 32)+"/cpu.stat", fmt.Sprintf("usage_usec %d\n", 100_000*k))
	f.write("cgroup/docker/"+strings.Repeat("ab", 32)+"/memory.current", "1048576\n")
	// Two processes and a kernel thread. Fields after the comm: state ppid
	// pgrp session tty tpgid flags minflt cminflt majflt cmajflt utime stime
	// cutime cstime priority nice threads itrealvalue starttime vsize rss ...
	proc := func(pid int, comm string, ticks, rssPages uint64) {
		f.write(fmt.Sprintf("proc/%d/stat", pid), fmt.Sprintf("%d (%s) S 1 1 1 0 -1 0 0 0 0 0 %d %d 0 0 20 0 1 0 100 1000 %d 0 0\n",
			pid, comm, ticks, ticks, rssPages))
	}
	proc(100, "postgres", 400*k, 25600) // 100 MB at 4 KB pages
	proc(200, "my (odd) name", 50*k, 2560)
	proc(2, "kthreadd", 0, 0)
}

func TestCollectFromFixtures(t *testing.T) {
	f := newFixture(t)
	c := New(Paths{Proc: filepath.Join(f.root, "proc"), Sys: filepath.Join(f.root, "sys"), Cgroup: filepath.Join(f.root, "cgroup")})
	c.Statfs = func(path string) (FsStat, error) {
		switch path {
		case "/":
			return FsStat{Blocks: 1000, Bfree: 300, Bavail: 250, Bsize: 4096, Files: 100, Ffree: 75}, nil
		case "/var":
			return FsStat{Blocks: 1000, Bfree: 100, Bavail: 100, Bsize: 4096, Files: 0}, nil
		}
		return FsStat{}, os.ErrNotExist
	}
	at := time.Unix(1_800_000_000, 0)
	c.Now = func() time.Time { return at }
	f.counters(1)
	first := c.Collect()
	if _, ok := first.Values["cpu_pct"]; ok {
		t.Fatal("a rate on the first sample")
	}
	if len(first.TopCPU) != 0 || len(first.TopMem) != 2 {
		t.Fatalf("first sample top: cpu %d mem %d", len(first.TopCPU), len(first.TopMem))
	}

	f.counters(2)
	at = at.Add(10 * time.Second)
	s := c.Collect()
	v := s.Values
	want := map[string]float64{
		// Deltas: user 1000 nice 100 system 500 idle 7000 iowait 400 irq 50 softirq 50 steal 100 = 9200.
		"cpu_pct":        round2(1800.0 / 9200 * 100),
		"cpu_pct.user":   round2(1100.0 / 9200 * 100),
		"cpu_pct.system": round2(500.0 / 9200 * 100),
		"cpu_pct.iowait": round2(400.0 / 9200 * 100),
		"cpu_pct.irq":    round2(100.0 / 9200 * 100),
		"cpu_pct.steal":  round2(100.0 / 9200 * 100),
		"load1":          0.8, "load5": 0.6, "load15": 0.4,
		"memory_pct":        62.5,
		"memory_used_bytes": 10_000_000 * 1024,
		"swap_pct":          25,
		"pressure.cpu_some": 1.2, "pressure.memory_some": 0.5, "pressure.memory_full": 0.25,
		"pressure.io_some": 3, "pressure.io_full": 2,
		"disk_pct:/":    round2(700.0 / 950 * 100),
		"inodes_pct:/":  25,
		"disk_pct:/var": 90,
		// sda: 2000 sectors read, 4000 written per step, over 10 s.
		"disk_read_bps:sda": 2000 * 512 / 10.0, "disk_write_bps:sda": 4000 * 512 / 10.0,
		"disk_read_bps:nvme0n1": 100 * 512 / 10.0, "disk_write_bps:nvme0n1": 300 * 512 / 10.0,
		"net_rx_bps:eth0": 1000, "net_tx_bps:eth0": 300, "net_rx_err_ps:eth0": 0.1, "net_tx_err_ps:eth0": 0.2,
		"net_rx_bps:docker0": 80, "net_tx_bps:docker0": 90, "net_rx_err_ps:docker0": 0, "net_tx_err_ps:docker0": 0,
		// Totals count only eth0, which has a device.
		"net_rx_bps": 1000, "net_tx_bps": 300,
		// 2 s of cpu over 10 s on 2 cores = 10 %.
		"cgroup.cpu_pct:docker-4f1c2a9e8b7d":      10,
		"cgroup.memory_bytes:docker-4f1c2a9e8b7d": 104857600,
		"cgroup.cpu_pct:nginx.service":            2.5,
		"cgroup.memory_bytes:nginx.service":       20971520,
		"cgroup.cpu_pct:docker-abababababab":      0.5,
		"cgroup.memory_bytes:docker-abababababab": 1048576,
	}
	for k, w := range want {
		got, ok := v[k]
		if !ok {
			t.Errorf("%s missing", k)
			continue
		}
		if d := got - w; d > 0.011 || d < -0.011 {
			t.Errorf("%s = %v, want %v", k, got, w)
		}
	}
	for k := range v {
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected metric %s = %v", k, v[k])
		}
	}
	// Processes: postgres used 800 ticks over 9200 total ticks.
	if len(s.TopCPU) != 2 || s.TopCPU[0].Comm != "postgres" || s.TopCPU[0].CPUPct != round2(800.0/9200*100) {
		t.Fatalf("top by cpu: %+v", s.TopCPU)
	}
	if s.TopCPU[1].Comm != "my (odd) name" {
		t.Errorf("a comm with parentheses: %q", s.TopCPU[1].Comm)
	}
	if s.TopMem[0].PID != 100 || s.TopMem[0].RSS != 25600*uint64(os.Getpagesize()) {
		t.Errorf("top by memory: %+v", s.TopMem)
	}
}

func TestMountsDedupeAndSkip(t *testing.T) {
	f := fixture{t, t.TempDir()}
	f.write("proc/self/mountinfo", mountinfo)
	var got []string
	for _, m := range Mounts(filepath.Join(f.root, "proc")) {
		got = append(got, m.Point+" "+m.FsType)
	}
	want := []string{"/ ext4", "/mnt/my disk ext4", "/var xfs"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("mounts %q, want %q", got, want)
	}
}

func TestMissingFilesAreSkipped(t *testing.T) {
	c := New(Paths{Proc: t.TempDir(), Sys: t.TempDir(), Cgroup: t.TempDir()})
	c.Collect()
	s := c.Collect()
	if len(s.Values) != 0 {
		t.Fatalf("values from nothing: %v", s.Values)
	}
}

// TestRealHost runs the collector against the /proc of whatever runs the
// test (a container in CI and locally) for a few samples.
func TestRealHost(t *testing.T) {
	if _, err := os.Stat("/proc/stat"); err != nil {
		t.Skip("no /proc here")
	}
	c := New(DefaultPaths())
	c.Collect()
	var s Sample
	for i := 0; i < 2; i++ {
		time.Sleep(600 * time.Millisecond)
		s = c.Collect()
	}
	for _, k := range []string{"cpu_pct", "load1", "memory_pct", "swap_pct"} {
		v, ok := s.Values[k]
		if !ok {
			t.Errorf("%s missing from a real sample", k)
		}
		if v < 0 || (strings.HasSuffix(k, "_pct") && v > 100) {
			t.Errorf("%s = %v out of range", k, v)
		}
	}
	self := false
	for _, p := range append(s.TopMem, s.TopCPU...) {
		if p.PID <= 0 || p.Comm == "" {
			t.Errorf("bad process %+v", p)
		}
		if p.PID == os.Getpid() {
			self = true
		}
	}
	if len(s.TopMem) == 0 {
		t.Error("no processes by memory")
	}
	_ = self // the test binary is usually but not always in the top 10
	t.Logf("%d metrics, e.g. cpu_pct=%v memory_pct=%v", len(s.Values), s.Values["cpu_pct"], s.Values["memory_pct"])
}
