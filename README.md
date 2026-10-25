# engram-agent

A small program that runs on a Linux server, keeps a history of how that
server is doing, and answers questions about it. It is the server half of
Engram's server management: it **reads** the host
and **sends** to Engram, and does nothing else. Doing things on a server
goes over SSH, never through the agent.

It keeps the history on the server, sends Engram a signed summary every
minute and an alert the moment one is raised, takes an inventory of the
server every five minutes and sends what changed in it (the observed state:
packages, network, ports, firewall, containers, users, SSH keys, Tailscale),
and answers the read commands that Engram's Servers app runs over SSH.

Documentation follows the Engram documentation standard v1: the map is
[docs/README.md](docs/README.md), the design [docs/architecture.md](docs/architecture.md),
and the reasons [docs/decisions/](docs/decisions/).

## What it is, in one paragraph

One static Go binary (`CGO_ENABLED=0`, linux amd64 and arm64, about 7 MB
stripped) run by systemd as the unprivileged user `engram-agent`. Every 10
seconds it reads `/proc`, `/sys` and cgroup v2, and writes the sample into one
SQLite file, `/var/lib/engram-agent/history.db`. Once a minute it rolls the
samples up into coarser tiers and applies retention and a size cap. Once
enrolled, it POSTs a signed report to Engram every minute (host facts, the
last minute's health, the events waiting) and an alert at once. The read
commands (`status`, `peaks`, `top`, `query`, `metrics`, `inventory`, `logs`)
run as whoever calls them; they are what a person runs on the box and what
Engram's Servers app runs over SSH. Beside the service, a systemd timer runs
the same binary as root every 5 minutes (`engram-agent snapshot`) to read what
the unprivileged agent cannot: the firewall, the containers, users and sudo,
SSH key fingerprints and Tailscale, into one file the agent reads.

## Security posture

- **Unprivileged.** The service runs as `engram-agent`, with no
  capabilities, under `NoNewPrivileges`, `ProtectSystem=strict` (it may write
  only `/var/lib/engram-agent`), `ProtectHome=read-only`, `PrivateTmp`,
  `PrivateDevices` and the rest of the unit's hardening
  ([`packaging/engram-agent.service`](packaging/engram-agent.service)).
- **One root part, the snapshot, with no input and no network.**
  `engram-agent snapshot` runs as root from a timer every 5 minutes
  ([`packaging/engram-agent-snapshot.service`](packaging/engram-agent-snapshot.service)).
  It keeps only `CAP_NET_ADMIN`, `CAP_NET_RAW` (reading netfilter) and
  `CAP_DAC_READ_SEARCH` (reading users' `authorized_keys`), may make no IP
  connection (`IPAddressDeny=any`; it talks only to local unix sockets and
  netlink), takes no input, and writes exactly one file,
  `/var/lib/engram-agent-snapshot/state.json`, under `ProtectSystem=strict`.
  It never runs a command for anyone and has no listening socket either.
  [Decision 0002](docs/decisions/0002-a-root-snapshot-and-the-observed-state-including-packages.md)
  says why it is a separate oneshot rather than privilege for the agent.
- **No listening port.** Neither ever opens a socket to listen on
  (`SocketBindDeny=any`). The agent's address families are limited to IPv4,
  IPv6, Unix and netlink (netlink to list the host's interfaces).
- **Reads only.** It reads counters and the names of processes and units. It
  never reads a process's environment, open files or command line arguments,
  and never runs a command for anyone. There is no command channel.
- **Sends only to Engram**: outbound HTTPS to the one origin it was enrolled
  with (plain http only to this machine, for tests). It sends health numbers,
  host facts, events and the observed state, the package list included;
  **never log lines, file contents, secrets or a key** (SSH keys only as
  their fingerprints, never the key itself).
- **No bearer secret.** It holds an ed25519 private key (`agent.key`, 0600,
  never sent) and signs every report; Engram stores only the public key.
- **Bounded.** `MemoryMax=256M`, `CPUQuota=20%`, `Nice=10`: a fault in the
  agent cannot starve the host it watches.
- **Who can read the history.** The state directory is
  `engram-agent:engram-agent 0750` and the agent's files are created `0640`
  (`UMask=0027`), so the agent's user and the members of group
  `engram-agent` can read it, nobody else. `install.sh --ssh-user deploy` adds
  the login the Servers app uses to that group. The snapshot's directory is
  `root:engram-agent 2750` (setgid, so the file gets the group without a
  chown) and its file `0640`: the same people can read it, only root writes
  it, and the agent cannot replace the directory under root.

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
  socket, which the agent does not have; the snapshot's `containers` section
  carries them (by name, not by id).
- **Top processes**: the 10 highest by CPU and the 10 highest by resident
  memory, each with pid, command name (`comm`), user id, CPU % machine-wide and
  RSS in bytes. Kernel threads are skipped.

## Where the history lives

One SQLite file, `/var/lib/engram-agent/history.db`, in WAL mode. The history
never leaves the server: Engram gets the last minute's summary, and reads
ranges over SSH with `query`, `peaks` and `top`. The same file holds the
outbox of events not yet acknowledged and the agent's own bookkeeping.

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
| `engram-agent inventory [--section S] [--json]` | what is on the server, taken now as the calling user; see "Inventory". `--section state` shows the observed-state sections the service would send |
| `engram-agent logs --unit U \| --container C \| --file F [--lines N] [--since T] [--grep TEXT] [--json]` | recent log lines, masked; see "Logs" |
| `engram-agent enrol --url ORIGIN --code CODE [--force]` | enrol with Engram (as user `engram-agent`; `install.sh --url --code` does it) |
| `engram-agent snapshot [--out DIR] [--json]` | as root: read the firewall, containers, users, SSH keys and Tailscale and write them to `DIR/state.json` (default `/var/lib/engram-agent-snapshot`); `--json` prints instead of writing. What the snapshot timer runs; see "The root snapshot" |
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
Also:

- `"alerts": {"memory_pct": {"warn": 85, "crit": 95, "for_s": 600, "clear_for_s": 120, "clear_fraction": 0.95}, "swap_pct": {"off": true}}`
  changes the alert rules by name (every key optional).
- `"log_files": ["/var/log/*", "/var/log/*/*"]` (the default): the glob
  patterns `logs --file` may read.
- `"report": false` stops reporting while still keeping history.

## Install, update, uninstall

Releases are published on GitHub
([releases](https://github.com/tetrixdev/engram-agent/releases)), built by
this repository's workflow from a version tag. Each holds the two binaries,
`install.sh`, the three systemd units (`engram-agent.service`,
`engram-agent-snapshot.service` and `.timer`), and `SHA256SUMS` over all six. Nothing is
downloaded or updated by itself: a server runs the version someone installed
on it, until someone installs another.

As root, on the server, for release `v0.1.0`:

```sh
curl -fsSLO https://github.com/tetrixdev/engram-agent/releases/download/v0.1.0/install.sh
sudo sh install.sh --version v0.1.0 --ssh-user deploy
```

`--version` downloads that release's `SHA256SUMS` and the binary for this
machine's architecture, and stops unless the binary's sha256 is the one
`SHA256SUMS` lists and the binary reports that version. `--sha256 <hex>` pins
the expected value as well, for whoever took it from somewhere other than the
release itself.

```sh
sudo sh install.sh --version v0.2.0                 # update: the same command with a newer release
sudo sh install.sh --binary ./engram-agent-linux-amd64 --sha256 <hex>   # a binary you built
sudo sh install.sh --uninstall                      # service, snapshot timer and binary go; history, identity, last snapshot and user stay
sudo sh install.sh --uninstall --purge              # and those too
```

### Verifying a release

- **Checksums.** `sha256sum --check --ignore-missing SHA256SUMS` beside the
  downloaded files; `install.sh --version` does this for the binary.
- **Who built it.** Every file in a release carries a build provenance
  attestation, signed keylessly through Sigstore: GitHub vouches that this
  repository's workflow built those exact bytes from that tag's commit. Check
  one on any machine with the GitHub CLI:
  `gh attestation verify engram-agent-linux-amd64 --repo tetrixdev/engram-agent`
  (or `install.sh`, or any other asset).
- **Releases cannot change.** The repository has GitHub's immutable releases
  on: once published, a release's tag and files cannot be replaced.

It creates the system user and group `engram-agent` (no home, no login
shell), adds it to `systemd-journal` and `adm` where those exist, creates
`/var/lib/engram-agent` (`engram-agent:engram-agent 0750`) and
`/var/lib/engram-agent-snapshot` (`root:engram-agent 2750`), installs the
binary at `/usr/local/bin/engram-agent` after checking its sha256 and that it
runs on this architecture, installs the three units, runs the snapshot once,
enables the snapshot timer (`--now`), and enables and (re)starts the service.
Running it again converges on the same result and restarts the service only
when the binary or its unit changed; an update is the same command with the
new binary. A binary without the `snapshot` command (before v0.2.0) gets no
snapshot units.
`--url` and `--code` enrol with Engram (as user `engram-agent`, so the key is
its own); the running service notices the new identity within a minute.

## Building and testing

```sh
go vet ./... && go test ./...
CGO_ENABLED=0 GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o engram-agent-linux-arm64 ./cmd/engram-agent
```

Without Go on the machine, in Docker:
`docker run --rm -u $(id -u):$(id -g) -e HOME=/tmp -v "$PWD":/src -w /src golang:1.24-bookworm go test ./...`.
The tests read fixture trees of `/proc`, `/sys` and cgroup files written by
the tests themselves, check the downsampling arithmetic, the tier choice,
retention and the size cap against a real SQLite file, and run the collector
and every command against the real `/proc` of the machine running them. The
snapshot's tests parse `iptables-save` fixtures (Docker's and Tailscale's
chains, escaped quotes in comments), talk to a fake Docker Engine on a unix
socket, and read passwd, group, sudoers and `authorized_keys` fixtures
(options, comments, garbage lines, a FIFO). The report loop runs against a
stand-in Engram (`httptest`) that verifies every signature, including a
package list cut into three parts; one test enrols the real binary's code
path with it and runs the service until a signed `server.observed` arrives. CI
runs the same and builds both architectures (`.github/workflows/ci.yml`); a
tag `vX.Y.Z` also publishes the release.

**Dependencies**: one, `modernc.org/sqlite`, a pure-Go SQLite, so the binary
stays static and builds for arm64 without a C cross-compiler. Everything else
(ed25519, HTTP, JSON, flags) is Go's standard library. It is pinned at
v1.46.0, the last release that builds with Go 1.24.

## Layout

- `cmd/engram-agent/`: the command line.
- `internal/collect/`: reading `/proc`, `/sys` and cgroups; rates between samples.
- `internal/store/`: the SQLite history: tiers, downsampling, queries, retention, the cap.
- `internal/config/`: the optional configuration file.
- `internal/identity/`: the key pair, the fingerprint, identity.json, the signature.
- `internal/report/`: the outbox, the HTTP client, the report loop and its backoff.
- `internal/alerts/`: the saturation rules and their hysteresis.
- `internal/inventory/`: OS, kernel, packages, updates, units, ports, users, sshd; the summary's findings.
- `internal/snapshot/`: the root snapshot: firewall, containers, users and sudo, SSH key fingerprints, Tailscale; the atomic write.
- `internal/state/`: the `state.observed` sections, their sha256 and parts, port scopes, the firewall and snapshot findings.
- `internal/logs/`: `logs` and the masking of secret-looking strings.
- `internal/agent/`: the service: what runs when, and which events each change makes.
- `testdata/signature-vector.json`: a fixed signature test vector for Engram's side.
- `packaging/`: the three systemd units and the installer.
- `docs/`: the map, the architecture and the decision records.

## Enrolling and reporting (wire protocol v1)

`engram-agent enrol --url https://engram.example.org --code ABCD-EFGH-JKLM`
makes the key pair (`agent.key`, PKCS #8 PEM, 0600) unless one exists, POSTs
`/agent/v1/enrol` with the code, the raw public key (base64), hostname,
version, OS and architecture, and writes `identity.json` (`{url, agent_id,
fingerprint, report_every_s, enrolled_at}`, 0640). It prints the
**fingerprint**: the first 10 bytes of sha256 of the raw 32-byte public key,
base32 (RFC 4648, uppercase, no padding), as four groups of four
(`KZDV-VJ2U-MNDU-YAUF`), for the person to compare with the Servers app. If
Engram answers with a different fingerprint than the agent computes, the
enrolment is not kept.

Every report is `POST /agent/v1/report` with `X-Engram-Agent`,
`X-Engram-Time` (unix seconds) and `X-Engram-Signature`: base64 of the ed25519
signature over `"engram-agent-v1\n" + agent_id + "\n" + time + "\n" +
hex(sha256(body))`. [`testdata/signature-vector.json`](testdata/signature-vector.json)
is a fixed vector (seed, public key, fingerprint, agent id, time, body, the
signed string and the signature) that Engram's side checks against; Go's
tests regenerate it with `go test ./internal/identity -run Vector -update`.

- **Every minute** (or Engram's `report_every_s`, kept between 15 s and an
  hour): `{agent_version, host, health, events}`. `host` is hostname, OS,
  running kernel, architecture, cores, memory, boot time and the public SSH
  host keys (`/etc/ssh/ssh_host_*_key.pub`, type and key without the
  comment). `health` is the last minute: `cpu_pct` and `memory_pct` as
  `{avg, max}`, `net` as averages, and the latest `load1`, `swap_pct`,
  pressure and per-mount `disk`.
- **At once**, when an alert is raised or resolved: an events-only report.
- **Events** wait in the outbox (on disk) until a 200 acknowledges them; a
  resend carries the same `key`. At most 20 per report, the report under 256
  KB (fewer events when they are large), each state under 64 KB. A queue
  longer than one report goes out in consecutive reports. The outbox keeps at
  most 1000 events (the oldest go first).
- **When Engram says no**: a network error, a 5xx or a 429 backs off (10 s,
  doubling, at most 10 minutes; 429 honours Retry-After). `401 clock` logs how
  far this server's clock is from Engram's `Date` and backs off the same
  way. `410` (the server was removed in Engram) stops sending, keeps
  collecting, logs it once and tries again once an hour; `401 unknown_agent`
  or `bad_signature` also retries hourly. `413` halves the batch; a single
  event Engram still refuses is dropped and logged. An alert raised during a
  backoff waits for the next try. On stop the service sends what is queued,
  for at most five seconds.
- **Not enrolled**: history is kept, nothing is sent and no events are
  queued. On a (new) enrolment the agent clears the outbox and sends its
  current state anew: the summary, every observed-state section and every
  raised alert; findings start over.

`status` shows the enrolment, the fingerprint, the reporting state (`ok`,
`retrying`, `removed`, `unauthorized`, `clock`) and when Engram last accepted
a report.

### Events

Event refs are the agent's own ids; Engram prefixes them with the agent id.

- `server.observed`, ref `host`, sent when the summary changes (it is
  compared by its sha256), with exactly these keys: `hostname, os, kernel,
  kernel_newest, arch, cpu_cores, memory_bytes, disk_bytes, boot_time,
  reboot_required, reboot_packages, packages_count, packages_sha256,
  updates_count, security_updates_count, unattended_upgrades, failed_units,
  listening, login_users, ssh {port, password_auth, root_login},
  containers_count, agent_version, ssh_host_keys`.
- `state.observed`, one per section of the observed state (see "The observed
  state"), sent when the section changed, with exactly these keys: `section,
  collected_at, sha256, part, parts, items, meta, error`.
- `alert.raised` / `alert.resolved`, ref the metric (`memory_pct`,
  `disk_pct:/var`, `firewall.uncommented_rules`): `rule, metric, level,
  threshold, value, peak, since`, and for resolved also `until, duration_s`.
- `finding.opened` / `finding.resolved`, ref the finding key: `kind,
  category, severity, title, detail, since, subject`. A finding whose title or
  detail changes is sent as `finding.opened` again, with its first `since`.

### Alerts

| Rule (= ref for one metric) | Metric | warn | crit | sustained for |
|---|---|---|---|---|
| `memory_pct` | `memory_pct` | > 90 | > 97 | 5 min |
| `disk_pct` | `disk_pct:<mount>`, one alert per mount | > 85 | > 95 | at once |
| `inodes_pct` | `inodes_pct:<mount>` | > 85 | > 95 | at once |
| `cpu_pct` | `cpu_pct` | > 90 | | 10 min |
| `pressure.memory_full` | `pressure.memory_full` (avg10) | > 5 | | 2 min |
| `pressure.io_full` | `pressure.io_full` (avg10) | > 20 | | 5 min |
| `swap_pct` | `swap_pct` | > 50 | | 10 min |
| `firewall_uncommented` | `firewall.uncommented_rules`: the firewall rules without a reason (see Findings) | > 0 | | at once |

Raised at `warn` once the value has stayed over the warn threshold for the
duration (`since` is when it first crossed). Raised again, at `crit`, once it
has stayed over the crit threshold for the same duration; the level never
steps back down within an episode. Resolved once it has stayed **under 95 %
of the warn threshold** (85.5 for 90) for **2 minutes**; between that and the
threshold it stays raised. `peak` is the highest value of the episode. A
metric that disappears (a mount removed) counts as recovered. Episodes are
saved in the history file, so a restart neither forgets a raised alert nor
raises it twice.

`firewall_uncommented` is judged from the snapshot at each inventory rather
than from samples: raised (warn, threshold 0, `value` the number of rules)
the first time a rule lacks a reason, resolved (with `value` 0) when none
does. While the snapshot is not ok it is left as it is. It is kept in the
history file like the others and re-sent on a new enrolment.

### Inventory

Taken at start, every 5 minutes, and whenever `/var/lib/dpkg/status`
changes; the pending updates hourly and on a dpkg change (the counts in
between are the last ones). All of it unprivileged:

| Section | What, and from where |
|---|---|
| `summary` | the server.observed state above |
| `os` | `/etc/os-release` PRETTY_NAME, hostname, architecture, boot time |
| `kernel` | the running kernel (`/proc/sys/kernel/osrelease`) and the installed `linux-image-*` packages, newest by dpkg version order; `/var/run/reboot-required` and `.pkgs` |
| `packages` | every installed package from dpkg's status file: name, version, source, arch; with count and sha256 over `name\tversion\tarch\n`, sorted |
| `updates` | `apt-get -s -o Debug::NoLocking=true dist-upgrade` as the calling user: each `Inst` of an installed package is an update, a security one when an origin is a `-security` pocket. It reads apt's lists as they are and never refreshes them. Measured on an Ubuntu 24.04 host as a normal user: 2.4 s for 33 updates. Plus whether unattended-upgrades is on (`APT::Periodic::Unattended-Upgrade` and the package) |
| `services` | `systemctl --failed --plain --no-legend` |
| `ports` | listening TCP and UDP sockets from `/proc/net/{tcp,tcp6,udp,udp6}` with their address; no process names (those need root) |
| `users` | accounts in `/etc/passwd` whose shell is not nologin, false, sync, shutdown or halt |
| `ssh` | Port, PasswordAuthentication and PermitRootLogin from `/etc/ssh/sshd_config` and the files it Includes, read as sshd does (first value wins, Match blocks skipped). **The files, not `sshd -T`**, which needs root. A value is `null` when a file that could have set it first cannot be read (Ubuntu's `50-cloud-init.conf` is often 0600), and OpenSSH's default (yes, prohibit-password) when nothing sets it. No sshd_config: port 0, both null |
| `containers` | running docker containers by short id, from their cgroups (names need the docker socket) |

`server.observed` carries the package list's count and sha256; the list
itself goes in the `packages` section of the observed state.

`listening` in the summary lists `proto/port` for ports some non-loopback
address listens on; ports bound only to 127.0.0.1 or ::1 are left out (the
`ports` section has them).

### The observed state

At every inventory the agent builds these sections and sends each one whose
sha256 (of the canonical JSON of `{items, meta, error}`: keys sorted, no
whitespace) differs from the one it last sent:

| Section | From | Items |
|---|---|---|
| `packages` | dpkg's status file and `/var/lib/apt/extended_states` | `[name, version, source, arch, manual]`; `manual` is false only when apt marked the package `Auto-Installed: 1` (an `Architecture: all` package is matched under the native architecture, as apt records it); source as dpkg lists it (may be `foo (1.2-3)`) |
| `network` | the host's interfaces (netlink) | `{interface, address, family, scope}`, loopback and the `veth*` half of each container left out; scope `public`, `private` (RFC 1918, fc00::/7), `tailnet` (100.64.0.0/10, fd7a:115c:a1e0::/48) or `link_local` |
| `ports` | `/proc/net/{tcp,tcp6,udp,udp6}` | `{proto, port, addresses, scope}`: `public` when any address is unspecified or public, else `tailnet` when every one is, `loopback` when every one is, else `private`. UDP ports in the ephemeral range are left out |
| `firewall`, `containers`, `users`, `ssh_keys`, `tailscale` | the snapshot's file, as written | see "The root snapshot" |
| `snapshot` | the snapshot file's presence and age | none; meta `{status: ok, missing, stale (over 30 minutes old) or unreadable, collected_at, error}` |

While the snapshot is not ok its five sections are not sent, so the last ones
sent stand. `collected_at` is when the data was read (the snapshot's own time
for its sections). The sha256 last sent per section is kept in the history
file and forgotten on a new enrolment.

Each event's state stays under 48 KB of JSON (Engram takes at most 64 KB).
`packages` always uses the ref `state:packages:<i>` (i from 1), even in one
part; any other section is ref `state:<section>`, and only if it outgrew one
part would it be cut the same way. Every part carries the whole section's
`sha256`, its `part` and `parts`; `meta` only in part 1 (`{}` in the others).
The event key is `state:<section>:<part>:<first 16 hex of sha256>:<unix
seconds when queued>`: Engram keeps every key it has seen, so a section that
changes back to an earlier state (a container stopped and started again)
needs a new key to be heard. A resend of a queued event keeps its key.

### The root snapshot

`engram-agent snapshot` (as root, from `engram-agent-snapshot.timer`: a
minute after boot, then every 5 minutes) writes
`/var/lib/engram-agent-snapshot/state.json`: `{version: 1, collected_at,
agent_version, sections}`, each section `{items, meta, error}`. A section that
cannot be read carries its own error; the others are unaffected. The file is
written atomically (a new temp file in the same directory opened
`O_EXCL|O_NOFOLLOW`, fsync, rename), mode 0640, group `engram-agent`.

| Section | From | Items, sorted |
|---|---|---|
| `firewall` | `iptables-save -t filter` and `ip6tables-save -t filter` (from /usr/sbin or /sbin) | one per `-A` line, chains sorted, rules in their order within a chain: `{family: v4\|v6, chain, rule, comment, target}`; `rule` without the `-m comment --comment` part, whitespace collapsed; `comment` unescaped; `target` after `-j` or `-g`. Every chain, Docker's and Tailscale's included. Meta: the built-in chains' `policies` per family, and `backend` (`nf_tables` or `legacy`) |
| `containers` | the Docker Engine API on `/var/run/docker.sock` (`GET /v1.41/containers/json?all=1`, no docker CLI) | `{name, image, image_id, state, compose_project, compose_service, published}`, `published` like `0.0.0.0:443->443/tcp` or `[::]:443->443/tcp`. No socket: none, meta `docker: false` |
| `users` | `/etc/passwd`, `/etc/group`, `/etc/sudoers` and `/etc/sudoers.d/*` | the accounts that can log in, plus root: `{login, uid, shell, groups, sudo: nopasswd\|password\|none}` (a rule line for the login or one of its groups containing `ALL`; with `NOPASSWD:` it is nopasswd) |
| `ssh_keys` | each such user's `~/.ssh/authorized_keys` and `authorized_keys2` | `{login, type, fingerprint: SHA256:..., comment, options}`. Never the key itself |
| `tailscale` | `tailscale status --json` | this machine only: `{hostname, dns_name, online, addresses, tags, backend_state}`; `NoState` when tailscaled cannot be reached. Not installed: none, meta `installed: false` |

### Findings

| Key | Kind | Category, severity | Open while |
|---|---|---|---|
| `pending_reboot` | pending_reboot | maintenance, medium | `/var/run/reboot-required` exists |
| `failed_unit:<unit>` | failed_unit | maintenance, medium | systemd lists the unit as failed |
| `ssh_password_auth` | ssh_password_auth | security, medium | sshd's files allow password logins (explicitly or by default) |
| `ssh_root_login` | ssh_root_login | security, high for `yes`, low for any other value but `no` (key-only root login, OpenSSH's default) | PermitRootLogin is not `no` |
| `kernel_not_running_newest` | kernel_not_running_newest | maintenance, low | the newest installed kernel is not the running one |
| `firewall_uncommented:<family>:<chain>:<first 12 hex of sha256(rule)>` | firewall_rule_uncommented | security, high | a rule in INPUT, FORWARD, OUTPUT or DOCKER-USER, not a jump to a chain named `DOCKER*` or `ts-*`, has no comment matching `^[a-z0-9][a-z0-9_.-]{0,40}: .{20,}$` (a key, a colon, a space, 20 or more characters of why), e.g. `-m comment --comment "web: proxy serves the sites; 80 for ACME"`. Judged only from an ok snapshot whose firewall section has no error; otherwise the open ones stand |
| `snapshot_not_running` | snapshot_not_running | maintenance, medium | the snapshot's status has not been ok for over 30 minutes; check `systemctl status engram-agent-snapshot.timer` |

A finding is opened with `since` the time the agent first saw it, and
resolved when the next inventory no longer sees it. Listening ports are no
longer judged by the agent (v0.1's `new_port` and its enrolment baseline are
gone; Engram compares the `ports` section with what the server is declared
to expose): an open `new_port` finding is resolved once after the upgrade.

### Logs

`logs` runs as the calling user (the SSH user, not the agent):
`--unit` reads the journal through `journalctl` (needs group `systemd-journal`
or `adm` for system units), `--container` runs `docker logs` (needs group
`docker`), `--file` reads a file matching `log_files` (the path and the
file a symlink points at must both match). `--lines` is at most 500, the
answer at most 64 KB (the newest lines are kept), `--since` takes
`"2026-10-19 14:00"` or `1h` (not for files), `--grep` keeps lines containing
the text, searching the last 20 000 lines. Names are checked against a strict
pattern and commands run without a shell.

Masking replaces, in every line, with `[redacted: <what>]`: private key
blocks, AWS access key ids, GitHub, GitLab, Slack and Stripe tokens, `sk-`
API keys (OpenAI, Anthropic), Google API keys, JWTs, bearer and basic
credentials in Authorization headers, the password in `scheme://user:pass@`
URLs, and the value of `key=value` or `"key": "value"` pairs whose key names
a password, secret, token, API or access key, private key, client secret or
credential. The marker format is the ai-bridge's (`src/local/scrub.ts` in
tetrixdev/ai-bridge), whose redaction replaces known values; it has no
pattern list, so the patterns were written here. It is hygiene, not
containment.

## Not built yet

- Self-update, on purpose: a server changes version only when someone runs
  `install.sh --version` on it.
- Process names on ports and `sshd -T`: they need root and are not in the
  snapshot, so the Servers app reads them over SSH.
