# Documentation map

Read in this order. Reference material still lives in the top-level
[README](../README.md); each line names its section.

- [architecture.md](architecture.md): purpose, quality goals, context, the containers (agent, snapshot, history file, Engram), key concepts, risks.
- [decisions/](decisions/): why it is built this way, one record per decision.
  - [0001](decisions/0001-its-own-public-repository-released-from-github.md): its own public repository, a static Go binary released from GitHub, no self-update.
  - [0002](decisions/0002-a-root-snapshot-and-the-observed-state-including-packages.md): a root snapshot, and the agent sends the observed state including the package list.
- [README: Security posture](../README.md#security-posture): what it may and may not do, the snapshot included.
- [README: What it collects](../README.md#what-it-collects): every metric, its unit and OpenTelemetry name.
- [README: Where the history lives](../README.md#where-the-history-lives): tiers, p95, the size cap, choosing a tier.
- [README: The command line](../README.md#the-command-line): every command and its JSON.
- [README: Install, update, uninstall](../README.md#install-update-uninstall): install.sh, verifying a release.
- [README: Enrolling and reporting](../README.md#enrolling-and-reporting-wire-protocol-v1): the wire protocol, events, alerts, inventory, the observed state, findings, logs.
- [README: Layout](../README.md#layout): where the code lives.
