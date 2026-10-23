Documentation: follows Engram documentation standard v1.

# engram-agent: for agents working in this repository

The server half of Engram's server management: a static Go binary that keeps
a server's health history, describes what is on it, and sends both to
Engram. Read [docs/README.md](docs/README.md) before larger work, and the
accepted records in [docs/decisions/](docs/decisions/) before changing what
they cover.

## Commands

Without Go on the machine, everything runs in Docker (give each a timeout):

```sh
# formatting, vet and every test (what CI runs); gofmt must print nothing
docker run --rm -u $(id -u):$(id -g) -e HOME=/tmp -e GOFLAGS=-modcacherw -v "$PWD":/src -w /src \
  golang:1.24-bookworm sh -c 'gofmt -l . ; go vet ./... && go test ./...'
# the smallest test: one package, one test
docker run ... golang:1.24-bookworm go test ./internal/state -run TestEventsChunking
# a static binary
docker run ... -e CGO_ENABLED=0 golang:1.24-bookworm go build -trimpath -ldflags "-s -w -X main.Version=0.0.0-dev" -o engram-agent ./cmd/engram-agent
# the installer parses
sh -n packaging/install.sh
```

`engram-agent inventory --section state --json` shows what the service would
send as `state.observed`; `sudo engram-agent snapshot --json` what the root
snapshot reads, without writing anything.

## Non-negotiables

- **Reads and sends only.** No command channel, no remote execution, no
  action on the host. Doing things goes over SSH, never through the agent.
- **No listening port**, ever (`SocketBindDeny=any` in both units).
- **No self-update.** A server changes version only when a person runs
  `install.sh --version`.
- **The agent stays unprivileged**: user `engram-agent`, no capabilities.
  Do not add a capability, the docker group or sudo to it (decision 0002).
- **The root snapshot takes no input and opens no network connection**
  (`IPAddressDeny=any`; unix sockets and netlink only), keeps only
  CAP_NET_ADMIN, CAP_NET_RAW and CAP_DAC_READ_SEARCH, and writes exactly one
  file. Do not give it flags that change what it reads, or a config file.
- **Never send or store** the agent's private key, any secret, a key blob
  (SSH keys go as fingerprints only), file contents, log lines, a process's
  environment or command line. Logs read for `logs` are masked and go only to
  the caller, never into a report.
- **Sends only to the enrolled Engram**, signed; plain http only to this machine.
- **Standard library only**, plus `modernc.org/sqlite`. The binary stays
  static (`CGO_ENABLED=0`).
- **Event state keys are exactly what the Servers app declares.** Adding a
  key to `server.observed`, `state.observed`, an alert or a finding is a
  change on both sides.
- **A unit file changed means its heredoc in `install.sh` changes too**
  (`packaging/packaging_test.go` checks).

## Where things live

- `cmd/engram-agent/`: the command line (`run`, `snapshot`, the read commands, `enrol`).
- `internal/agent/`: the service: what runs when, which events each change makes, the firewall alert.
- `internal/snapshot/`: the root snapshot (firewall, containers, users, ssh keys, tailscale) and its atomic write.
- `internal/state/`: the `state.observed` sections, their sha256, chunking, port scope, firewall and snapshot findings.
- `internal/inventory/`: the unprivileged inventory and the `server.observed` summary; its findings.
- `internal/collect/`, `internal/store/`: sampling, and the SQLite history with tiers and the cap.
- `internal/report/`: the outbox, the signed client, the report loop.
- `internal/alerts/`: the saturation rules. `internal/logs/`: `logs` and masking.
- `packaging/`: the three systemd units, `install.sh`, and the test keeping them in step.
- `docs/`: [architecture](docs/architecture.md), [decisions](docs/decisions/). Reference: [README.md](README.md).

## Load-bearing decisions

- 0001: its own public MIT repository; static Go binary; immutable attested releases from a tag; installed by hand; no self-update.
- 0002: a root oneshot snapshot on a timer (no input, no network, one file) beside the unprivileged agent; the agent sends `state.observed` including the package list; `new_port` removed; every firewall rule a person writes needs a reason comment.
- The history stays on the server (13 months, avg/p95/max per bucket); Engram gets the last minute and events, and reads ranges over SSH.
- A `state.observed` key ends in a send stamp: Engram keeps every key for good, so a key per content would drop a section that changes back.

## Conventions

- Plain, exact prose in docs and messages; no marketing.
- Tests use fixture trees and fakes (a fake docker socket, a stand-in Engram over httptest); a command runner and a filesystem root are injectable everywhere a test needs them.
- Every command the code runs has a timeout and a fixed environment (`LANG=C`, a fixed `PATH`).
