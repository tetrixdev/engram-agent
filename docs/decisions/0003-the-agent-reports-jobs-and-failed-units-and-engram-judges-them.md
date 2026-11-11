---
status: accepted
date: 2026-11-11
supersedes:
superseded_by:
revisit_when: a job that matters runs from cron or inside a container rather than as a systemd timer; or the units section's hourly cap proves too slow for a job declared to succeed within an hour or two
---
# The agent reports jobs and failed units, and Engram judges them

## Context

A scheduled job on a server (a nightly database backup on a systemd timer)
that fails shows only in `systemctl --failed` and the journal. Up to v0.2 the
agent turned every unit `systemctl --failed` listed into a `failed_unit`
finding of its own. Three things were wrong with that, seen on a real
server on 10 Nov 2026: the finding resolved whenever the unit ran again
(while it was `activating` it is not listed failed) and opened again when the
run failed, six times in one day for one harmless unit; a person had no way
to say "this unit is known to fail, leave it"; and nothing could say that a
job had not succeeded for too long, because the agent knew neither which
jobs matter nor when one last succeeded. Engram's Servers app holds what a
person declares about a server; the agent takes no input (0002).

Jasper approved the feature on 11 Nov 2026: the Servers app tells the person
when a scheduled job on one of their servers fails, or when a backup is
stale. Engram's record of the same day says how the app judges and tells.

## Decision

- **A `units` section of the observed state**, read by the unprivileged
  agent with `systemctl show` (systemd answers any user): every loaded
  timer's service (a job), every failed unit, every failed timer. Per item
  its state and result now, whether it is `failed`, since when, its last
  run and exit status, its last success and its timer's next run.
- **`failed` holds through a new run.** A unit judged failed stays failed
  while a run is in progress, and turns false only when a run ends without
  failing, it is reset, or it is gone. One failure is one failure.
- **The agent keeps each job's last success** in its history file, because
  systemd forgets a unit's exit time on a reboot and keeps no "last
  success" once a run has failed.
- **A failure or recovery goes at once; a change of times only at most once
  an hour.** Otherwise a timer every few minutes (the snapshot's own) would
  send the section with every inventory.
- **No `failed_unit` finding of the agent's own any more.** The Servers app
  judges the section with what the person declared (a unit known to fail, a
  job that must succeed within N hours) and opens its own findings; an open
  `failed_unit` finding is resolved once after the upgrade, as `new_port`
  was in 0002. `server.observed` keeps `failed_units` as it was.

## Consequences

- A server on an older agent keeps its own `failed_unit` findings and gets
  no job monitoring until it is updated.
- Whether a job worked is what systemd says of its exit. The agent reads
  no file a job writes (a status file, a backup) and no log line; a job
  must exit non-zero when it fails.
- Jobs run by cron are not seen.
- A job's last success is at most an hour old in Engram.

## Options considered

- **Keep the agent's finding and fix the flapping only**: no way to declare
  a unit known to fail, and still no staleness. Rejected.
- **A list of jobs to watch in the agent's configuration**: a second place
  to declare what a server should have, beside Engram's expected state,
  and input to the agent. Rejected.
- **Reading a status file the job writes**: a file's contents leave the
  server, and every job would need its own format. Rejected.
