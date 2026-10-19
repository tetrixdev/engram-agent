# engram-agent

A small program that runs on a Linux server, keeps a history of how that
server is doing, and answers questions about it. It is the server half of
Engram's server management (decision 0355): it **reads** the host
and **sends** to Engram, and does nothing else. Doing things on a server
goes over SSH, never through the agent.

This version collects and keeps history and answers the read commands.
Enrolling with Engram and reporting to it come next (see "Not built yet").

## What it is, in one paragraph

One static Go binary (`CGO_ENABLED=0`, linux amd64 and arm64, about 7 MB
stripped) run by systemd as the unprivileged user `engram-agent`. Every 10
seconds it reads `/proc`, `/sys` and cgroup v2, and writes the sample into one
SQLite file, `/var/lib/engram-agent/history.db`. Once a minute it rolls the
samples up into coarser tiers and applies retention and a size cap. The read
commands (`status`, `peaks`, `top`, `query`, `metrics`) open that file
read-only; they are what a person runs on the box and what Engram's Servers app
runs over SSH.

## Security posture

- **Unprivileged.** It runs as `engram-agent`, with no capabilities, under
  `NoNewPrivileges`, `ProtectSystem=strict` (it may write only
  `/var/lib/engram-agent`), `ProtectHome=read-only`, `PrivateTmp`,
  `PrivateDevices` and the rest of the unit's hardening
  ([`packaging/engram-agent.service`](packaging/engram-agent.service)). There
  is no root helper.
- **No listening port.** It never opens a socket to listen on
  (`SocketBindDeny=any`); its address families are limited to IPv4, IPv6 and
  Unix.
- **Reads only.** It reads counters and the names of processes and units. It
  never reads a process's environment, open files or command line arguments,
  and never runs a command for anyone. There is no command channel.
- **Sends only to Engram** (once reporting is built): outbound HTTPS to the
  one origin it was enrolled with. This version sends nothing at all.
- **Bounded.** `MemoryMax=256M`, `CPUQuota=20%`, `Nice=10`: a fault in the
  agent cannot starve the host it watches.
- **Who can read the history.** The state directory is
  `engram-agent:engram-agent 0750` and the agent's files are created `0640`
  (`UMask=0027`), so the agent's user and the members of group
  `engram-agent` can read it, nobody else. `install.sh --ssh-user deploy` adds
  the login the Servers app uses to that group.

## What it collects

Every 10 seconds. A rate needs two samples, so rates start with the second.
Percentages are 0 to 100. "Machine-wide" means all cores together are 100 %,
so a process using one core of eight fully shows 12.5.

| Metric | What | Unit | OpenTelemetry |
|---|---|---|---|
| `cpu_pct` | CPU busy (not idle, not iowait), machine-wide | % | `system.cpu.utilization` summed over the busy states, ×100 |
| `cpu_pct.user`, `.system`, `.iowait`, `.irq`, `.steal` | CPU per state (`user` includes nice, `irq` includes softirq) | % | `system.cpu.utilization{cpu.mode=user\|system\|iowait\|interrupt\|steal}` ×100 |
| `load1`, `load5`, `load15` | load averages | | `system.cpu.load_average.1m`, `.5m`, `.15m` |
| `memory_pct` | memory used: total minus MemAvailable | % | `system.memory.utilization{system.memory.state=used}` ×100 |
| `memory_used_bytes` | the same in bytes | bytes | `system.memory.usage{system.memory.state=used}` |
| `swap_pct` | swap used (0 without swap) | % | `system.paging.utilization{system.paging.state=used}` ×100 |
| `pressure.cpu_some`, `pressure.memory_some`, `pressure.memory_full`, `pressure.io_some`, `pressure.io_full` | Linux pressure stall information, avg10 | % of time | none (Linux PSI, `/proc/pressure`) |
| `disk_pct:<mount>` | space used on a real filesystem, as `df` computes it | % | `system.filesystem.utilization{system.filesystem.mountpoint}` ×100 |
| `inodes_pct:<mount>` | inodes used | % | from `system.filesystem.inodes.usage` |
| `disk_read_bps:<dev>`, `disk_write_bps:<dev>` | bytes read and written per second, whole devices | B/s | rate of `system.disk.io{disk.io.direction=read\|write, system.device}` |
| `net_rx_bps:<if>`, `net_tx_bps:<if>` | bytes received and sent per second | B/s | rate of `system.network.io{network.io.direction=receive\|transmit, network.interface.name}` |
| `net_rx_err_ps:<if>`, `net_tx_err_ps:<if>` | receive and transmit errors per second | 1/s | rate of `system.network.errors` |
| `net_rx_bps`, `net_tx_bps` | totals over interfaces backed by a device (eth0, not docker0 or a tunnel, so bytes are not counted twice); over every interface when none has a device | B/s | rate of `system.network.io`, summed |
| `cgroup.cpu_pct:<cgroup>` | CPU of a container or service, machine-wide | % | `container.cpu.utilization` ×100 |
| `cgroup.memory_bytes:<cgroup>` | memory charged to it (`memory.current`) | bytes | `container.memory.usage` |

Names are short and stable; what follows the colon is the thing measured.

- **Mounts**: real filesystems only (a `/dev/` source, or zfs, btrfs, xfs, ext4,
  nfs, cifs), one per device, the device's own root rather than a bind mount
  inside it (a service's private `/tmp`, a container volume). tmpfs, overlay,
  squashfs (snaps), proc, sysfs and the like are skipped.
- **Devices**: whole devices `/sys/block` lists; partitions, loop, ram, sr and
  fd devices are skipped.
- **Interfaces**: every one except `lo` and the `veth*` half of each
  container, which come and go with containers and would each leave a series
  behind.
- **Cgroups**: `docker-<first 12 hex of the container id>` for a container
  (systemd and cgroupfs drivers alike), and the unit name (`nginx.service`)
  for every service under `system.slice`. Container names need the docker
  socket, which the agent does not have; the Servers app maps ids to names
  over SSH.
- **Top processes**: the 10 highest by CPU and the 10 highest by resident
  memory, each with pid, command name (`comm`), user id, CPU % machine-wide and
  RSS in bytes. Kernel threads are skipped.

## Where the history lives

One SQLite file, `/var/lib/engram-agent/history.db`, in WAL mode. Nothing
leaves the server in this version.

| Tier | Bucket | Kept | Built from |
|---|---|---|---|
| `10s` | the raw samples | 48 hours | the collector |
| `1m` | 1 minute | 14 days | the raw samples in it |
| `5m` | 5 minutes | 90 days | the 1m buckets in it |
| `1h` | 1 hour | 13 months (396 days) | the 5m buckets in it |

Every bucket keeps the **average**, the **95th percentile**, the **maximum**
and **when the maximum was seen**, and the number of samples. So a 10-second
spike is still visible a year later as the maximum of its hour.

- **The 1-minute p95 is exact**: the 95th percentile of the six raw samples in
  that minute, by linear interpolation between the nearest ranks (the method
  numpy and spreadsheets use by default).
- **The p95 of the 5-minute and 1-hour tiers is approximated**, because the
  raw samples are gone by then: it is the 95th percentile of the finer
  buckets' p95 values, each weighted by its number of samples, and never above
  the maximum. It is exact when the load is steady. When one finer bucket held
  a burst it reads high (one hot minute in an hour lifts the hour's p95 towards
  that minute's p95), which errs on the side of showing load rather than
  hiding it. The average, maximum and its time are exact in every tier.
- **Top processes**: every sample is kept 48 hours; the sample at each
  minute's CPU peak and memory peak is kept 14 days, so "what was running at
  the 14:05 peak" can be answered for two weeks.
- **Size.** Values are stored as integers in hundredths, which SQLite packs
  into 1 to 4 bytes. Measured: about 16 bytes per raw sample and 30 per
  bucket, so one metric kept for the whole retention takes about 2 MB, and a
  host with 30 containers and the usual systemd services (around 180 metrics)
  about 350 MB to 450 MB.
- **The size cap** (default 500 MB, `max_db_mb` in the configuration) is
  checked every minute against the bytes the file holds. Over it, the agent
  cuts the **oldest rows of the finest tier first**, because every minute of
  those is also kept in a coarser tier: the cap costs resolution before it
  costs coverage. Each tier is cut back at most to a floor (raw to 6 hours, 1m
  to 2 days, 5m to 14 days, 1h to 30 days) before the next tier is thinned.

### Choosing the tier for a range

A query asks for a range and about how many points. Of the tiers that still
hold data back to the start of the range, the agent takes the one that answers
in the most points without going over the number asked, once its buckets are
merged in whole groups; on a tie the coarser, which reads fewer rows. "The last
6 hours in 120 points" is the 1m tier, three minutes per point; "the last 30
days in 120 points" is the 1h tier, six hours per point. When no tier reaches
back to the start (the agent is younger than the range), the coarsest that has
data answers. Merged points keep avg (weighted), p95 (as above; exact when
merged from raw) and max. The coarser tiers end at their last complete bucket,
so a range ending now may lack the current minute, five minutes or hour.

## The command line

Every read command takes `--json`; with it an error is also printed as
`{"error": "..."}` on stdout, with exit code 1. Times are RFC 3339
(`2026-10-19T14:05:00Z`), a date-time read as UTC (`2026-10-19T14:05`), unix
seconds, `now`, or a duration back from now (`-1h`, `90m`, `2d`). Every
command takes `--db` and `--config` (default `/etc/engram-agent/config.json`).

| Command | Answers |
|---|---|
| `engram-agent run` | the service: sample every 10 s, maintain once a minute |
| `engram-agent status [--json]` | the latest sample, the last hour's peak of each core metric and disk, the enrolment state, the history file's size |
| `engram-agent peaks [--from -1h] [--to now] [--metric NAME\|PREFIX*] [--n 3] [--json]` | per metric: avg, p95, max over the range and its highest peaks, never two from neighbouring buckets |
| `engram-agent top [--at TIME] [--json]` | the top 10 processes by CPU and by memory at the sample nearest that time (default the latest) |
| `engram-agent query --json '<request>'` | one metric over a range |
| `engram-agent metrics [--json]` | the metric names this host has recorded |
| `engram-agent version` | the version |

`query` takes `{"metric": "cpu_pct", "from": "-6h", "to": "now", "points": 120}`
(`from` defaults to `-1h`, `to` to now, `points` to 120, at most 2000) and answers

```json
{ "metric": "cpu_pct", "tier": "1m", "step_s": 180,
  "from": "2026-10-19T06:00:00Z", "to": "2026-10-19T12:00:00Z",
  "points": [ { "t": "2026-10-19T06:00:00Z", "avg": 12.5, "p95": 31.2, "max": 80.1, "max_at": "2026-10-19T06:01:40Z" } ],
  "summary": { "avg": 14.1, "p95": 40.3, "max": 97.4, "max_at": "2026-10-19T09:12:10Z", "samples": 2160 } }
```

`peaks --json` answers `{from, to, metrics: [{metric, tier, avg, p95, max,
peaks: [{at, value}]}]}`; `top --json` answers `{at, by_cpu: [...],
by_memory: [...]}`, each process `{pid, comm, uid, cpu_pct, rss_bytes}`.

The read commands never write: they open the file read-only (while the
service is stopped they open it immutable, since SQLite then needs no shared
memory file), so they work for any member of group `engram-agent`.

## Configuration

`/etc/engram-agent/config.json` is optional; every key is.

```json
{ "state_dir": "/var/lib/engram-agent", "db": "/var/lib/engram-agent/history.db",
  "max_db_mb": 500, "proc": "/proc", "sys": "/sys", "cgroup": "/sys/fs/cgroup" }
```

`max_db_mb: -1` turns the cap off. `proc`, `sys` and `cgroup` exist for tests
and for running the agent in a container against a host's mounted `/proc`.

## Install, update, uninstall

[`packaging/install.sh`](packaging/install.sh), as root, on the server:

```sh
sh install.sh --binary ./engram-agent-linux-amd64 --sha256 <hex> --ssh-user deploy
sh install.sh --binary https://example.org/engram-agent-linux-amd64 --sha256 <hex>   # a URL needs --sha256
sh install.sh --uninstall            # service and binary go; history, identity and user stay
sh install.sh --uninstall --purge    # and those too
```

It creates the system user and group `engram-agent` (no home, no login
shell), adds it to `systemd-journal` and `adm` where those exist, creates
`/var/lib/engram-agent` (`engram-agent:engram-agent 0750`), installs the binary
at `/usr/local/bin/engram-agent` after checking its sha256 and that it runs on
this architecture, installs the unit, and enables and (re)starts it. Running
it again converges on the same result and restarts the service only when the
binary or the unit changed; an update is the same command with the new binary.
`--url` and `--code` enrol with Engram once the binary has `enrol`.

## Building and testing

```sh
cd agent
go vet ./... && go test ./...
CGO_ENABLED=0 GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o engram-agent-linux-arm64 ./cmd/engram-agent
```

Without Go on the machine, in Docker:
`docker run --rm -u $(id -u):$(id -g) -e HOME=/tmp -v "$PWD":/src -w /src golang:1.24-bookworm go test ./...`.
The tests read fixture trees of `/proc`, `/sys` and cgroup files written by
the tests themselves, check the downsampling arithmetic, the tier choice,
retention and the size cap against a real SQLite file, and run the collector
and every command against the real `/proc` of the machine running them. CI
runs the same and builds both architectures (job `agent` in
`.github/workflows/test.yml`).

**Dependencies**: one, `modernc.org/sqlite`, a pure-Go SQLite, so the binary
stays static and builds for arm64 without a C cross-compiler. Everything else
(ed25519, HTTP, JSON, flags) is Go's standard library. It is pinned at
v1.46.0, the last release that builds with Go 1.24.

## Layout

- `cmd/engram-agent/`: the command line.
- `internal/collect/`: reading `/proc`, `/sys` and cgroups; rates between samples.
- `internal/store/`: the SQLite history: tiers, downsampling, queries, retention, the cap.
- `internal/config/`: the optional configuration file.
- `packaging/`: the systemd unit and the installer.

## Not built yet

- Enrolling with Engram and the signed report every minute (wire protocol v1),
  alerts, the inventory and `logs`: the next change.
- Signed releases and self-update. They need a release on GitHub and a signing
  key built into the installer, which is a decision for the owner; until then a
  binary is built from this directory and installed with its sha256.
