---
type: explanation
---
# Architecture

## Purpose

engram-agent is the server half of Engram's server management. On each Linux
server it keeps a 13-month history of how the server is doing, describes what
is on it, and sends both to the one Engram it was enrolled with. It reads and
sends; it never acts. Doing things on a server goes over SSH, never through
the agent.

## Quality goals

1. **It cannot be used against the server it watches.** No listening port,
   no command channel, no self-update, no bearer secret. The long-running,
   networked part holds no privilege; the part that holds some has no
   network and no input.
2. **It cannot hurt the server it watches.** Bounded memory and CPU, a size
   cap on its history, every command with a timeout.
3. **What it says is exact.** Every number has a stated unit and method; what
   it cannot read is reported as unknown or as an error, never guessed.
4. **Anyone can check what runs.** A public repository, one static binary,
   immutable attested releases, installed by hand.

## Context (C4 level 1)

- **A person** installs it with `install.sh`, enrols it with a one-time code
  from the Servers app, and runs the read commands on the box.
- **Engram** (the Servers app) receives its signed reports over HTTPS, and
  runs its read commands over SSH for history and logs.
- **The host**: `/proc`, `/sys`, cgroups, dpkg and apt's files, systemd,
  and (through the snapshot only) netfilter, the docker socket, sudoers,
  users' `authorized_keys` and tailscaled.

## Containers (C4 level 2)

| Container | Runs as | Does |
|---|---|---|
| `engram-agent run` (`engram-agent.service`) | user `engram-agent`, no capabilities | samples every 10 s into the history file; inventory every 5 min; reads the snapshot file; sends signed reports and events to Engram |
| `engram-agent snapshot` (`engram-agent-snapshot.service`, its timer every 5 min) | root with CAP_NET_ADMIN, CAP_NET_RAW, CAP_DAC_READ_SEARCH only; `IPAddressDeny=any` | reads the firewall, containers, users and sudo, SSH key fingerprints and Tailscale; writes `/var/lib/engram-agent-snapshot/state.json` |
| The history file | `/var/lib/engram-agent/history.db`, `0640 engram-agent:engram-agent` | samples, tiers, top processes, the event outbox, the agent's bookkeeping |
| The read commands (`status`, `query`, `inventory`, `logs`, ...) | whoever calls them (the SSH user, in group `engram-agent`) | answer from the history file or the host, read-only |
| Engram | elsewhere | stores events, compares observed with declared state, raises Needs you |

The snapshot and the agent share only the file: root writes it, the agent's
group reads it. The directory is root's and outside the agent's own, so the
agent cannot swap it under root.

## Key concepts

- **Tiers**: raw 10 s for 48 hours, then 1 minute, 5 minutes, 1 hour, each
  bucket with avg, p95 and max.
- **Events**: `server.observed`, `state.observed`, `alert.raised` /
  `.resolved`, `finding.opened` / `.resolved`, queued in the outbox until
  Engram acknowledges them; a resend carries the same key.
- **Sections** of the observed state, each sent only when its sha256 changed,
  cut into parts under 48 KB.
- **Findings** are what the agent judges by itself; **alerts** are saturation
  over time, plus the firewall rule the agent raises itself.

## Risks

- **The snapshot runs as root.** It parses output of programs root runs
  (`iptables-save`, `tailscale`) and files users control (`authorized_keys`,
  read without following FIFOs and capped in size). Mitigated by no input,
  no network, three capabilities and a read-only filesystem but one
  directory.
- **The package list and the observed state leave the server.** They go only
  to the enrolled Engram, signed; no key material or file contents, and SSH
  keys only as fingerprints.
- **A report is at most 256 KB and 20 events.** A very large section (a host
  with thousands of firewall rules) is cut into parts; a single item over
  64 KB would be refused by Engram and logged.
- **Engram keeps every event key for good**, so a key must be unique per
  sending, not per content (see decision 0002).
