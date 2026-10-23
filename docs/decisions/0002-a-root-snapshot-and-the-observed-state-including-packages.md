---
status: accepted
date: 2026-10-23
supersedes:
superseded_by:
revisit_when: Engram needs a host fact the snapshot cannot read without more than CAP_NET_ADMIN, CAP_NET_RAW and CAP_DAC_READ_SEARCH, or without a network connection; or the state.observed events outgrow what a report may carry
---
# A root snapshot, and the agent sends the observed state including the package list

## Context

Engram's Servers app now compares what a server is observed to run with a
declared expected state (Engram's decision records 0424 to 0426, written in
parallel with this change). For that it needs, unattended and without SSH:
the firewall rules, the containers and the ports they publish, the users and
their sudo, the SSH keys that may log in, the Tailscale identity, and the
package list for CVE matching.

The agent cannot read most of that. It runs as an unprivileged user with no
capabilities (decision 0001): the netfilter tables need CAP_NET_ADMIN, the
docker socket is root-equivalent, sudoers is root-only, and other users'
`authorized_keys` sit in home directories it cannot enter. Until now the
Servers app read those over SSH, and fetched the package list over SSH
whenever its sha256 changed.

## Decision

- **A root oneshot, `engram-agent snapshot`**, started by
  `engram-agent-snapshot.timer` (a minute after boot, then every 5 minutes).
  It takes no input, opens no network connection (`IPAddressDeny=any`; it
  talks only to local unix sockets and netlink), keeps only CAP_NET_ADMIN,
  CAP_NET_RAW and CAP_DAC_READ_SEARCH, and writes one file atomically:
  `/var/lib/engram-agent-snapshot/state.json`, `0640 root:engram-agent`, in a
  root-owned setgid directory outside the agent's own, so the agent cannot
  swap it under root. Each section fails on its own.
- **The agent stays unprivileged.** It reads that file, and sends
  `state.observed` events: `packages` (the full list, with apt's manual
  flag), `network`, `ports` with a scope, the snapshot's five sections, and
  the snapshot's own status. A section goes only when its sha256 changed;
  a large one is cut into parts under 48 KB.
- **`new_port` is removed**, with its enrolment baseline: ports are judged in
  Engram against the declaration. An open `new_port` finding is resolved once
  on upgrade.
- **Every firewall rule a person writes needs a reason**: a rule in INPUT,
  FORWARD, OUTPUT or DOCKER-USER without a comment shaped
  `<key>: <why, 20+ characters>` opens `firewall_rule_uncommented` and raises
  the agent's own `firewall_uncommented` alert. The snapshot not running for
  30 minutes opens `snapshot_not_running`.

## Consequences

- The agent is no longer the whole of what runs on a server: there is now a
  root component. It is kept small, without input or network, and is read
  in `internal/snapshot/` alone.
- The package list leaves the server in reports (one to a few parts of under
  48 KB, sent again only when it changes); the Servers app no longer needs
  SSH for it.
- The agent's unit gains AF_NETLINK, to list the host's interfaces.
- A `state.observed` key carries a send stamp after the sha256, because
  Engram keeps every key it has seen: a section that changes back to an
  earlier state (a container stopped and started again) must still be heard.

## Options considered

- **The agent in group docker with CAP_NET_ADMIN**: rejected. The docker
  socket is root, so the long-running, networked agent would be
  root-equivalent; the point of the split is that what talks to the network
  holds nothing.
- **Reading over SSH from Engram** (as before): rejected for unattended
  comparison; it needs an SSH login with sudo on every server, used on a
  schedule without a person present.
- **A scanner such as Trivy on the server**: rejected. A large, often
  updated, networked tool with its own vulnerability database, run as root,
  to answer what the package list sent to Engram answers there.
