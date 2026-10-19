// Package collect reads the host's health from /proc, /sys and cgroup v2,
// unprivileged, and turns counters into rates between two samples.
//
// Every path is relative to a configurable root (Paths), so the tests run the
// same code against fixtures. Nothing here writes, and nothing here needs root:
// a process's command and owner are readable by anyone, a process's open files
// and its environment are not read at all.
package collect

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Paths are the roots the collector reads. The defaults are the real ones.
type Paths struct {
	Proc   string // /proc
	Sys    string // /sys (block devices, network interfaces)
	Cgroup string // /sys/fs/cgroup (the cgroup v2 unified hierarchy)
}

// DefaultPaths are the host's own.
func DefaultPaths() Paths {
	return Paths{Proc: "/proc", Sys: "/sys", Cgroup: "/sys/fs/cgroup"}
}

// FsStat is what statfs says about one mounted filesystem.
type FsStat struct {
	Blocks, Bfree, Bavail uint64 // in units of Bsize
	Bsize                 uint64
	Files, Ffree          uint64
}

// Proc is one process in a top-10 list.
type Proc struct {
	PID    int     `json:"pid"`
	Comm   string  `json:"comm"`
	UID    int     `json:"uid"`
	CPUPct float64 `json:"cpu_pct"`   // percent of the whole machine (all cores = 100)
	RSS    uint64  `json:"rss_bytes"` // resident memory in bytes
}

// Sample is one collection: metric name to value, plus the top processes.
type Sample struct {
	T      time.Time
	Values map[string]float64
	TopCPU []Proc // empty on the first sample: a rate needs two
	TopMem []Proc
}

// Collector holds the previous sample's counters, so rates can be computed.
type Collector struct {
	P      Paths
	Statfs func(path string) (FsStat, error)
	Now    func() time.Time
	TopN   int

	prev *counters
}

type counters struct {
	at       time.Time
	cpu      []uint64 // the aggregate "cpu" line of /proc/stat
	disk     map[string][2]uint64
	net      map[string][4]uint64 // rx bytes, rx errs, tx bytes, tx errs
	cgroup   map[string]uint64    // usage_usec
	proc     map[int]uint64       // utime+stime in ticks
	cpuTotal uint64               // sum of the aggregate cpu line (ticks across every core)
}

// New returns a collector over the given roots with the real statfs.
func New(p Paths) *Collector {
	return &Collector{P: p, Statfs: realStatfs, Now: time.Now, TopN: 10}
}

func realStatfs(path string) (FsStat, error) {
	var s syscall.Statfs_t
	if err := syscall.Statfs(path, &s); err != nil {
		return FsStat{}, err
	}
	return FsStat{Blocks: s.Blocks, Bfree: s.Bfree, Bavail: s.Bavail, Bsize: uint64(s.Bsize), Files: s.Files, Ffree: s.Ffree}, nil
}

// Collect takes one sample. Rates (cpu, disk io, network, cgroup cpu, process
// cpu) are only present from the second call on.
func (c *Collector) Collect() Sample {
	now := c.Now()
	v := map[string]float64{}
	cur := &counters{at: now, disk: map[string][2]uint64{}, net: map[string][4]uint64{}, cgroup: map[string]uint64{}, proc: map[int]uint64{}}
	var elapsed float64
	if c.prev != nil {
		elapsed = now.Sub(c.prev.at).Seconds()
	}
	rate := elapsed > 0

	ncpu := c.cpu(v, cur, rate)
	c.load(v)
	c.memory(v)
	c.pressure(v)
	c.disks(v)
	c.diskIO(v, cur, rate, elapsed)
	c.network(v, cur, rate, elapsed)
	c.cgroups(v, cur, rate, elapsed, ncpu)
	topCPU, topMem := c.processes(cur, rate)

	c.prev = cur
	return Sample{T: now, Values: v, TopCPU: topCPU, TopMem: topMem}
}

func (c *Collector) path(root string, parts ...string) string {
	return filepath.Join(append([]string{root}, parts...)...)
}

func readLines(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

func parseU(s string) uint64 {
	n, _ := strconv.ParseUint(s, 10, 64)
	return n
}

func pct(part, whole float64) float64 {
	if whole <= 0 {
		return 0
	}
	p := part / whole * 100
	if p < 0 {
		return 0
	}
	return round2(p)
}

func round2(f float64) float64 {
	return float64(int64(f*100+0.5)) / 100
}

// cpu reads /proc/stat. It returns the number of cores.
func (c *Collector) cpu(v map[string]float64, cur *counters, rate bool) int {
	ncpu := 0
	for _, l := range readLines(c.path(c.P.Proc, "stat")) {
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		if f[0] == "cpu" {
			for _, s := range f[1:] {
				cur.cpu = append(cur.cpu, parseU(s))
			}
		} else if strings.HasPrefix(f[0], "cpu") {
			ncpu++
		}
	}
	for len(cur.cpu) < 8 {
		cur.cpu = append(cur.cpu, 0)
	}
	// user nice system idle iowait irq softirq steal; guest is already in user.
	for _, n := range cur.cpu[:8] {
		cur.cpuTotal += n
	}
	if rate && c.prev != nil && len(c.prev.cpu) >= 8 {
		d := make([]float64, 8)
		for i := range d {
			d[i] = float64(cur.cpu[i] - c.prev.cpu[i])
			if cur.cpu[i] < c.prev.cpu[i] {
				d[i] = 0
			}
		}
		total := float64(cur.cpuTotal) - float64(c.prev.cpuTotal)
		if total > 0 {
			v["cpu_pct"] = pct(total-d[3]-d[4], total)
			v["cpu_pct.user"] = pct(d[0]+d[1], total)
			v["cpu_pct.system"] = pct(d[2], total)
			v["cpu_pct.iowait"] = pct(d[4], total)
			v["cpu_pct.irq"] = pct(d[5]+d[6], total)
			v["cpu_pct.steal"] = pct(d[7], total)
		}
	}
	if ncpu == 0 {
		ncpu = 1
	}
	return ncpu
}

func (c *Collector) load(v map[string]float64) {
	l := readLines(c.path(c.P.Proc, "loadavg"))
	if len(l) == 0 {
		return
	}
	f := strings.Fields(l[0])
	for i, name := range []string{"load1", "load5", "load15"} {
		if i < len(f) {
			if x, err := strconv.ParseFloat(f[i], 64); err == nil {
				v[name] = x
			}
		}
	}
}

// MemInfo reads /proc/meminfo into kB values by key.
func MemInfo(proc string) map[string]uint64 {
	m := map[string]uint64{}
	for _, l := range readLines(filepath.Join(proc, "meminfo")) {
		k, rest, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) > 0 {
			m[k] = parseU(f[0])
		}
	}
	return m
}

func (c *Collector) memory(v map[string]float64) {
	m := MemInfo(c.P.Proc)
	total, ok := m["MemTotal"]
	if !ok || total == 0 {
		return
	}
	avail, ok := m["MemAvailable"]
	if !ok {
		avail = m["MemFree"] + m["Buffers"] + m["Cached"]
	}
	used := float64(total) - float64(avail)
	v["memory_pct"] = pct(used, float64(total))
	v["memory_used_bytes"] = used * 1024
	if st := m["SwapTotal"]; st > 0 {
		v["swap_pct"] = pct(float64(st)-float64(m["SwapFree"]), float64(st))
	} else {
		v["swap_pct"] = 0
	}
}

// pressure reads avg10 of /proc/pressure/{cpu,memory,io}, some and full.
func (c *Collector) pressure(v map[string]float64) {
	for _, res := range []string{"cpu", "memory", "io"} {
		for _, l := range readLines(c.path(c.P.Proc, "pressure", res)) {
			f := strings.Fields(l)
			if len(f) < 2 || (f[0] != "some" && f[0] != "full") {
				continue
			}
			// The kernel writes a "full" line for cpu too (always zero at the
			// system level); it carries nothing, so it is not kept.
			if res == "cpu" && f[0] == "full" {
				continue
			}
			for _, kv := range f[1:] {
				if strings.HasPrefix(kv, "avg10=") {
					if x, err := strconv.ParseFloat(kv[6:], 64); err == nil {
						v["pressure."+res+"_"+f[0]] = x
					}
				}
			}
		}
	}
}

// Mount is one real filesystem.
type Mount struct {
	Point, FsType, Source, Dev string
}

var skipFs = map[string]bool{
	"tmpfs": true, "devtmpfs": true, "overlay": true, "proc": true, "sysfs": true, "cgroup": true,
	"cgroup2": true, "squashfs": true, "nsfs": true, "autofs": true, "mqueue": true, "debugfs": true,
	"tracefs": true, "securityfs": true, "pstore": true, "bpf": true, "configfs": true, "fusectl": true,
	"hugetlbfs": true, "devpts": true, "ramfs": true, "efivarfs": true, "binfmt_misc": true,
	"rpc_pipefs": true, "nfsd": true, "fuse.lxcfs": true, "fuse.snapfuse": true, "fuse.portal": true,
	"zram": true, "iso9660": true, "udf": true,
}

// Mounts lists the real filesystems from mountinfo: one per device, the
// device's own root rather than a bind mount of a directory inside it, and
// the shortest mount point when the same root is mounted twice (a service's
// PrivateTmp bind of /tmp, a container's volume).
func Mounts(proc string) []Mount {
	type cand struct {
		m    Mount
		root string
	}
	best := map[string]cand{}
	var order []string
	for _, l := range readLines(filepath.Join(proc, "self", "mountinfo")) {
		pre, post, ok := strings.Cut(l, " - ")
		if !ok {
			continue
		}
		a, b := strings.Fields(pre), strings.Fields(post)
		if len(a) < 5 || len(b) < 2 {
			continue
		}
		fstype, source := b[0], b[1]
		if skipFs[fstype] {
			continue
		}
		real := strings.HasPrefix(source, "/dev/") || fstype == "zfs" || fstype == "btrfs" ||
			strings.HasPrefix(fstype, "nfs") || fstype == "cifs" || fstype == "xfs" || fstype == "ext4"
		if !real {
			continue
		}
		point := unescapeMount(a[4])
		if strings.HasPrefix(point, "/proc") || strings.HasPrefix(point, "/sys") || strings.HasPrefix(point, "/snap/") {
			continue
		}
		dev, root := a[2], unescapeMount(a[3])
		c := cand{Mount{Point: point, FsType: fstype, Source: source, Dev: dev}, root}
		old, seen := best[dev]
		if !seen {
			order = append(order, dev)
			best[dev] = c
			continue
		}
		if len(root) < len(old.root) || (len(root) == len(old.root) && len(point) < len(old.m.Point)) {
			best[dev] = c
		}
	}
	out := make([]Mount, 0, len(order))
	for _, d := range order {
		out = append(out, best[d].m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Point < out[j].Point })
	return out
}

// unescapeMount undoes mountinfo's octal escapes (\040 for a space).
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func (c *Collector) disks(v map[string]float64) {
	for _, m := range Mounts(c.P.Proc) {
		s, err := c.Statfs(m.Point)
		if err != nil || s.Blocks == 0 {
			continue
		}
		// As df computes it: used over what a non-root user could reach.
		used := float64(s.Blocks - s.Bfree)
		v["disk_pct:"+m.Point] = pct(used, used+float64(s.Bavail))
		if s.Files > 0 {
			v["inodes_pct:"+m.Point] = pct(float64(s.Files-s.Ffree), float64(s.Files))
		}
	}
}

// diskIO reads /proc/diskstats for whole devices only (a name /sys/block knows).
func (c *Collector) diskIO(v map[string]float64, cur *counters, rate bool, elapsed float64) {
	for _, l := range readLines(c.path(c.P.Proc, "diskstats")) {
		f := strings.Fields(l)
		if len(f) < 10 {
			continue
		}
		name := f[2]
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") || strings.HasPrefix(name, "sr") || strings.HasPrefix(name, "fd") {
			continue
		}
		if _, err := os.Stat(c.path(c.P.Sys, "block", strings.ReplaceAll(name, "/", "!"))); err != nil {
			continue
		}
		// Sectors are 512 bytes in diskstats whatever the device's own size.
		cur.disk[name] = [2]uint64{parseU(f[5]) * 512, parseU(f[9]) * 512}
		if p, ok := c.prev.diskOf(name); ok && rate {
			v["disk_read_bps:"+name] = perSec(cur.disk[name][0], p[0], elapsed)
			v["disk_write_bps:"+name] = perSec(cur.disk[name][1], p[1], elapsed)
		}
	}
}

func (p *counters) diskOf(name string) ([2]uint64, bool) {
	if p == nil {
		return [2]uint64{}, false
	}
	x, ok := p.disk[name]
	return x, ok
}

func perSec(now, before uint64, elapsed float64) float64 {
	if now < before || elapsed <= 0 {
		return 0
	}
	return round2(float64(now-before) / elapsed)
}

// SkipInterface says which interfaces get no metrics of their own: loopback,
// and the veth half of every container, which come and go with containers
// and would each leave a series behind.
func SkipInterface(name string) bool {
	return name == "lo" || strings.HasPrefix(name, "veth")
}

func (c *Collector) network(v map[string]float64, cur *counters, rate bool, elapsed float64) {
	var totRx, totTx, allRx, allTx float64
	physical, any := false, false
	for _, l := range readLines(c.path(c.P.Proc, "net", "dev")) {
		name, rest, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		f := strings.Fields(rest)
		if len(f) < 16 || SkipInterface(name) {
			continue
		}
		cur.net[name] = [4]uint64{parseU(f[0]), parseU(f[2]), parseU(f[8]), parseU(f[10])}
		if c.prev == nil || !rate {
			continue
		}
		p, ok := c.prev.net[name]
		if !ok {
			continue
		}
		n := cur.net[name]
		rx, tx := perSec(n[0], p[0], elapsed), perSec(n[2], p[2], elapsed)
		v["net_rx_bps:"+name] = rx
		v["net_tx_bps:"+name] = tx
		v["net_rx_err_ps:"+name] = perSec(n[1], p[1], elapsed)
		v["net_tx_err_ps:"+name] = perSec(n[3], p[3], elapsed)
		allRx += rx
		allTx += tx
		any = true
		// The totals count interfaces backed by a device, so a bridge or a
		// tunnel carrying the same bytes as eth0 is not counted twice.
		if _, err := os.Stat(c.path(c.P.Sys, "class", "net", name, "device")); err == nil {
			physical = true
			totRx += rx
			totTx += tx
		}
	}
	if any {
		if !physical {
			totRx, totTx = allRx, allTx
		}
		v["net_rx_bps"] = round2(totRx)
		v["net_tx_bps"] = round2(totTx)
	}
}

// Cgroup is one container or service cgroup.
type Cgroup struct {
	Name string // docker-<12 hex> or the unit name, e.g. nginx.service
	Dir  string
}

// Cgroups lists docker containers (systemd and cgroupfs drivers) and systemd
// services under system.slice.
func Cgroups(root string) []Cgroup {
	var out []Cgroup
	sys, _ := os.ReadDir(filepath.Join(root, "system.slice"))
	for _, e := range sys {
		n := e.Name()
		if !e.IsDir() {
			continue
		}
		switch {
		case strings.HasPrefix(n, "docker-") && strings.HasSuffix(n, ".scope"):
			id := strings.TrimSuffix(strings.TrimPrefix(n, "docker-"), ".scope")
			out = append(out, Cgroup{Name: "docker-" + short(id), Dir: filepath.Join(root, "system.slice", n)})
		case strings.HasSuffix(n, ".service"):
			out = append(out, Cgroup{Name: n, Dir: filepath.Join(root, "system.slice", n)})
		}
	}
	dock, _ := os.ReadDir(filepath.Join(root, "docker"))
	for _, e := range dock {
		if e.IsDir() && len(e.Name()) >= 12 {
			out = append(out, Cgroup{Name: "docker-" + short(e.Name()), Dir: filepath.Join(root, "docker", e.Name())})
		}
	}
	return out
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func (c *Collector) cgroups(v map[string]float64, cur *counters, rate bool, elapsed float64, ncpu int) {
	for _, g := range Cgroups(c.P.Cgroup) {
		for _, l := range readLines(filepath.Join(g.Dir, "cpu.stat")) {
			f := strings.Fields(l)
			if len(f) == 2 && f[0] == "usage_usec" {
				cur.cgroup[g.Name] = parseU(f[1])
			}
		}
		if mem := readLines(filepath.Join(g.Dir, "memory.current")); len(mem) > 0 && mem[0] != "" {
			v["cgroup.memory_bytes:"+g.Name] = float64(parseU(strings.TrimSpace(mem[0])))
		}
		if c.prev == nil || !rate {
			continue
		}
		now, ok1 := cur.cgroup[g.Name]
		before, ok2 := c.prev.cgroup[g.Name]
		if ok1 && ok2 && now >= before {
			v["cgroup.cpu_pct:"+g.Name] = pct(float64(now-before), elapsed*1e6*float64(ncpu))
		}
	}
}

func (c *Collector) processes(cur *counters, rate bool) (byCPU, byMem []Proc) {
	ents, _ := os.ReadDir(c.P.Proc)
	page := uint64(os.Getpagesize())
	var all []Proc
	totalDelta := float64(0)
	if c.prev != nil {
		totalDelta = float64(cur.cpuTotal) - float64(c.prev.cpuTotal)
	}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		dir := c.path(c.P.Proc, e.Name())
		b, err := os.ReadFile(filepath.Join(dir, "stat"))
		if err != nil {
			continue
		}
		s := string(b)
		open, close := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
		if open < 0 || close < open {
			continue
		}
		comm := s[open+1 : close]
		f := strings.Fields(s[close+1:])
		// After the comm: state is field 3; utime 14, stime 15, rss 24 (1-based, man proc).
		if len(f) < 22 {
			continue
		}
		ticks := parseU(f[11]) + parseU(f[12])
		rss := parseU(f[21]) * page
		if rss == 0 && ticks == 0 {
			continue // kernel threads
		}
		cur.proc[pid] = ticks
		uid := -1
		if fi, err := os.Stat(dir); err == nil {
			if st, ok := fi.Sys().(*syscall.Stat_t); ok {
				uid = int(st.Uid)
			}
		}
		p := Proc{PID: pid, Comm: comm, UID: uid, RSS: rss, CPUPct: -1}
		if rate && totalDelta > 0 {
			if before, ok := c.prev.proc[pid]; ok && ticks >= before {
				p.CPUPct = pct(float64(ticks-before), totalDelta)
			}
		}
		all = append(all, p)
	}
	n := c.TopN
	if n <= 0 {
		n = 10
	}
	sort.Slice(all, func(i, j int) bool { return all[i].RSS > all[j].RSS })
	for i := 0; i < len(all) && i < n; i++ {
		byMem = append(byMem, all[i])
	}
	if rate {
		sort.SliceStable(all, func(i, j int) bool { return all[i].CPUPct > all[j].CPUPct })
		for i := 0; i < len(all) && len(byCPU) < n; i++ {
			if all[i].CPUPct >= 0 {
				byCPU = append(byCPU, all[i])
			}
		}
	}
	for i := range byMem {
		if byMem[i].CPUPct < 0 {
			byMem[i].CPUPct = 0
		}
	}
	return byCPU, byMem
}

// ReadLines reads a file's lines; nil when it cannot be read.
func ReadLines(path string) []string { return readLines(path) }
