---
status: accepted
date: 2026-10-20
supersedes:
superseded_by:
revisit_when: a server needs an update faster than a person can run one command on it, or GitHub releases stop being the place a stranger can check a build
---
# Its own public repository, a static Go binary released from GitHub

## Context

The agent began under `agent/` in Engram's own (private) repository. Engram's
decision records 0355 (2026-10-19) and 0392 (2026-10-20) settled what it is
and where a server's binary comes from. This record carries what they decided
for this repository, so it can be read here without Engram's.

An invited member's servers run whatever binary they are told to install. If
an Engram instance served the binary, whoever hosts that instance could push
changed code onto another person's servers.

## Decision

- **A static Go binary**: `CGO_ENABLED=0`, linux amd64 and arm64, the
  standard library plus `modernc.org/sqlite` (pure Go). A server needs
  nothing installed first.
- **Reads and sends only**: an unprivileged systemd service as user
  `engram-agent`, no listening socket, no command channel. Doing things on a
  server goes over SSH, never through the agent.
- **This repository, public, MIT** (github.com/tetrixdev/engram-agent), with
  the history of Engram's `agent/` (git subtree split).
- **A tag vX.Y.Z publishes a release from CI**: both binaries, `install.sh`,
  the systemd units and `SHA256SUMS` over them, each with a keyless build
  provenance attestation (Sigstore). Releases are immutable (the repository
  setting): a published release's tag and files cannot be replaced.
- **Installed and updated by hand**: `install.sh --version vX.Y.Z` checks the
  binary against `SHA256SUMS` and its reported version. An update is the same
  command with a newer tag. **No self-update.**

## Consequences

- A protocol change that touches both sides is two pull requests: this
  repository's release first, then Engram.
- What makes `SHA256SUMS` trustworthy is the immutable release and the
  attestation, which anyone can check with `gh attestation verify`.

## Options considered

- **Staying under `agent/` in Engram**: one pull request per protocol change,
  but a private repository nobody else can audit or install from.
- **Engram serving the binary**: rejected for the reason in Context; every
  instance would also become a distribution point to keep current.
- **A signing key pinned in install.sh**: one more secret to keep and rotate,
  for what the keyless attestation and immutable releases already give.
- **Self-update**: rejected by Jasper; a server changes code only when its
  person runs the command.
- **Rust**, **a container**, **SQLite through cgo**: see Engram's 0355; none
  keeps a single static binary that reads the host as simply.
