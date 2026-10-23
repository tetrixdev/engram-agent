#!/bin/sh
# Install, update or remove engram-agent on this server. Run as root.
#
#   install.sh --version vX.Y.Z [--sha256 HEX] [--ssh-user NAME]... [--url ORIGIN --code CODE]
#   install.sh --binary ./engram-agent [--sha256 HEX] ...
#   install.sh --uninstall [--purge]
#
# --version   a release of github.com/tetrixdev/engram-agent: downloads that
#             release's binary for this architecture and its SHA256SUMS, and
#             stops unless the binary's sha256 is the one SHA256SUMS lists.
#             The usual way to install and to update.
# --binary    instead: a binary you have, a local path, or an https URL (then
#             --sha256 is required). Give neither to keep the installed one.
# --sha256    the binary's expected sha256; the install stops on a mismatch.
#             With --version it is checked as well as SHA256SUMS.
# --ssh-user  a login that may run the read commands (status, query, ...):
#             added to group engram-agent. Repeatable.
# --url/--code  enrol with Engram: the origin and the one-time code from the
#             Servers app. Needs a binary that has `engram-agent enrol`.
# --uninstall stop and remove the service, the snapshot timer and the binary;
#             the history, the identity, the last snapshot and the user stay,
#             unless --purge is also given.
#
# Besides the agent (unprivileged) it installs engram-agent-snapshot.service
# and .timer: a root oneshot every 5 minutes that writes the firewall,
# containers, users, SSH keys and Tailscale into
# /var/lib/engram-agent-snapshot/state.json for the agent to read.
#
# Running it again is safe: it converges on the same result. Nothing updates
# by itself: an update is this command again with a newer --version.
set -eu

BIN_DST=/usr/local/bin/engram-agent
UNIT_DST=/etc/systemd/system/engram-agent.service
SNAP_SERVICE_DST=/etc/systemd/system/engram-agent-snapshot.service
SNAP_TIMER_DST=/etc/systemd/system/engram-agent-snapshot.timer
STATE=/var/lib/engram-agent
SNAP_DIR=/var/lib/engram-agent-snapshot
CONF_DIR=/etc/engram-agent
USER_NAME=engram-agent
RELEASES=https://github.com/tetrixdev/engram-agent/releases

binary="" version="" sha="" url="" code="" uninstall=0 purge=0 ssh_users=""

die() { echo "install.sh: $*" >&2; exit 1; }
say() { echo "engram-agent: $*"; }

while [ $# -gt 0 ]; do
	case "$1" in
	--version) version="${2:?--version needs a release tag, e.g. v0.1.0}"; shift 2 ;;
	--binary) binary="${2:?--binary needs a path or URL}"; shift 2 ;;
	--sha256) sha="${2:?--sha256 needs a value}"; shift 2 ;;
	--ssh-user) ssh_users="$ssh_users ${2:?--ssh-user needs a name}"; shift 2 ;;
	--url) url="${2:?--url needs the Engram origin}"; shift 2 ;;
	--code) code="${2:?--code needs the enrolment code}"; shift 2 ;;
	--uninstall) uninstall=1; shift ;;
	--purge) purge=1; shift ;;
	-h|--help) sed -n '2,32p' "$0"; exit 0 ;;
	*) die "unknown argument $1 (--help lists them)" ;;
	esac
done

if [ -n "$version" ]; then
	[ -z "$binary" ] || die "give --version or --binary, not both"
	case "$version" in
	v[0-9]*.[0-9]*.[0-9]*) ;;
	*) die "--version $version: expected a release tag such as v0.1.0" ;;
	esac
fi

[ "$(id -u)" = 0 ] || die "run as root (sudo sh install.sh ...)"

has_systemd() { [ -d /run/systemd/system ]; }

if [ "$uninstall" = 1 ]; then
	if has_systemd; then
		systemctl disable --now engram-agent-snapshot.timer 2>/dev/null || true
		systemctl stop engram-agent-snapshot.service 2>/dev/null || true
		systemctl disable --now engram-agent.service 2>/dev/null || true
	fi
	rm -f "$UNIT_DST" "$SNAP_SERVICE_DST" "$SNAP_TIMER_DST" "$BIN_DST"
	has_systemd && systemctl daemon-reload || true
	if [ "$purge" = 1 ]; then
		rm -rf "$STATE" "$SNAP_DIR" "$CONF_DIR"
		if id "$USER_NAME" >/dev/null 2>&1; then userdel "$USER_NAME" 2>/dev/null || true; fi
		if getent group "$USER_NAME" >/dev/null 2>&1; then groupdel "$USER_NAME" 2>/dev/null || true; fi
		say "removed, with its history, identity, snapshot and user"
	else
		say "removed; history and identity kept in $STATE, the last snapshot in $SNAP_DIR (--purge removes them and the user)"
	fi
	exit 0
fi

# The user and group: a system account with no home and no login.
if ! getent group "$USER_NAME" >/dev/null 2>&1; then
	groupadd --system "$USER_NAME"
fi
if ! id "$USER_NAME" >/dev/null 2>&1; then
	useradd --system --gid "$USER_NAME" --no-create-home --home-dir "$STATE" --shell /usr/sbin/nologin "$USER_NAME"
fi
for g in systemd-journal adm; do
	if getent group "$g" >/dev/null 2>&1; then usermod -aG "$g" "$USER_NAME"; fi
done
for u in $ssh_users; do
	id "$u" >/dev/null 2>&1 || die "--ssh-user $u: no such user"
	usermod -aG "$USER_NAME" "$u"
	say "$u may now run the read commands (from its next login)"
done

# The state directory: the agent writes it; its group reads it.
install -d -m 0750 -o "$USER_NAME" -g "$USER_NAME" "$STATE"
for f in "$STATE"/history.db "$STATE"/history.db-wal "$STATE"/history.db-shm; do
	[ -e "$f" ] && chown "$USER_NAME:$USER_NAME" "$f" && chmod 0640 "$f"
done
[ -e "$STATE/agent.key" ] && chown "$USER_NAME:$USER_NAME" "$STATE/agent.key" && chmod 0600 "$STATE/agent.key"
install -d -m 0755 "$CONF_DIR"

# The snapshot's directory: root writes it, the agent's group reads it. It is
# setgid, so the file root writes there has group engram-agent without a
# chown (the snapshot runs without CAP_CHOWN). Not inside $STATE, which the
# agent owns and could swap under root.
install -d -m 2750 -o root -g "$USER_NAME" "$SNAP_DIR"
chown root:"$USER_NAME" "$SNAP_DIR"
chmod 2750 "$SNAP_DIR"
if [ -e "$SNAP_DIR/state.json" ]; then chown root:"$USER_NAME" "$SNAP_DIR/state.json" && chmod 0640 "$SNAP_DIR/state.json"; fi

# The binary.
fetch() { # fetch URL FILE
	if command -v curl >/dev/null 2>&1; then curl -fsSL --proto '=https' -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then wget -q --https-only -O "$2" "$1"
	else die "neither curl nor wget is installed"; fi
}
changed=0
if [ -n "$version" ] || [ -n "$binary" ]; then
	tmp=$(mktemp)
	sums=$(mktemp)
	trap 'rm -f "$tmp" "$sums"' EXIT
	if [ -n "$version" ]; then
		case "$(uname -m)" in
		x86_64|amd64) arch=amd64 ;;
		aarch64|arm64) arch=arm64 ;;
		*) die "no release binary for $(uname -m); build one and give --binary" ;;
		esac
		asset="engram-agent-linux-$arch"
		base="$RELEASES/download/$version"
		fetch "$base/SHA256SUMS" "$sums" || die "could not download $base/SHA256SUMS (is $version a release?)"
		listed=$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1 }' "$sums")
		[ -n "$listed" ] || die "SHA256SUMS of $version lists no $asset"
		[ -z "$sha" ] || [ "$sha" = "$listed" ] || die "--sha256 $sha is not what SHA256SUMS of $version lists ($listed)"
		sha=$listed
		fetch "$base/$asset" "$tmp" || die "could not download $base/$asset"
	else
		case "$binary" in
		https://*|http://*)
			[ -n "$sha" ] || die "a downloaded binary needs --sha256"
			fetch "$binary" "$tmp" ;;
		*)
			[ -f "$binary" ] || die "--binary $binary: no such file"
			cp "$binary" "$tmp" ;;
		esac
	fi
	if [ -n "$sha" ]; then
		got=$(sha256sum "$tmp" | cut -d' ' -f1)
		[ "$got" = "$sha" ] || die "sha256 mismatch: expected $sha, got $got"
		say "sha256 checked: $got"
	fi
	chmod 0755 "$tmp"
	"$tmp" version >/dev/null 2>&1 || die "the binary does not run here (wrong architecture? this is $(uname -m))"
	if [ -n "$version" ] && [ "v$("$tmp" version)" != "$version" ]; then
		die "the binary of $version says it is v$("$tmp" version)"
	fi
	if ! cmp -s "$tmp" "$BIN_DST" 2>/dev/null; then
		install -m 0755 -o root -g root "$tmp" "$BIN_DST"
		changed=1
		say "installed $("$BIN_DST" version) at $BIN_DST"
	fi
fi
[ -x "$BIN_DST" ] || die "no binary at $BIN_DST: give --version (or --binary)"

# The unit: the copy beside this script, else the one embedded below (kept
# identical by packaging/packaging_test.go). Groups this system lacks are
# left out of SupplementaryGroups, or systemd would refuse to start it.
here=$(dirname "$0")
unit=$(mktemp)
if [ -f "$here/engram-agent.service" ]; then
	cp "$here/engram-agent.service" "$unit"
else
	cat >"$unit" <<'UNIT'
# engram-agent: collects this server's health into /var/lib/engram-agent and
# (once enrolled) reports it to Engram. Unprivileged, read-only on the system,
# no listening socket. Installed by packaging/install.sh.
[Unit]
Description=Engram server agent (health history, reports to Engram)
Documentation=https://github.com/tetrixdev/engram-agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/engram-agent run
User=engram-agent
Group=engram-agent
# Reading the journal and /var/log for `engram-agent logs` run as the agent.
SupplementaryGroups=systemd-journal adm
# Files it creates (history.db and its -wal/-shm) are readable by the group,
# so a member (the SSH user the Servers app connects as) can run the read
# commands; nobody else can.
UMask=0027
Restart=on-failure
RestartSec=10s

# Hardening: it reads /proc, /sys and a few files, and writes only its state.
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/engram-agent
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
# AF_NETLINK: listing the host's network interfaces and addresses.
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
CapabilityBoundingSet=
AmbientCapabilities=
# It never listens; nothing may connect to it.
IPAccounting=yes
SocketBindDeny=any

# Bounded, so a fault in it can never starve the host it watches.
MemoryMax=256M
CPUQuota=20%
Nice=10

[Install]
WantedBy=multi-user.target
UNIT
fi
groups=""
for g in systemd-journal adm; do
	if getent group "$g" >/dev/null 2>&1; then groups="$groups $g"; fi
done
groups=${groups# }
if [ -n "$groups" ]; then
	sed -i "s/^SupplementaryGroups=.*/SupplementaryGroups=$groups/" "$unit"
else
	sed -i '/^SupplementaryGroups=/d' "$unit"
fi
if ! cmp -s "$unit" "$UNIT_DST" 2>/dev/null; then
	install -m 0644 "$unit" "$UNIT_DST"
	changed=1
fi
rm -f "$unit"

# The root snapshot's service and timer, likewise beside this script or
# embedded below; only with a binary that has the snapshot command.
snap=0 snap_changed=0
if "$BIN_DST" help 2>&1 | grep -q '^  snapshot '; then
	snap=1
	for f in engram-agent-snapshot.service engram-agent-snapshot.timer; do
		tmpu=$(mktemp)
		if [ -f "$here/$f" ]; then
			cp "$here/$f" "$tmpu"
		elif [ "$f" = engram-agent-snapshot.service ]; then
			cat >"$tmpu" <<'SNAPSERVICE'
# engram-agent-snapshot: as root, every 5 minutes (engram-agent-snapshot.timer),
# reads what the unprivileged agent cannot (the firewall, the docker socket,
# sudoers, authorized_keys, tailscale's status) into one file the agent
# reads. No input, no network connection, one file written. Installed by
# packaging/install.sh.
[Unit]
Description=Engram server agent: root snapshot (firewall, containers, users, SSH keys, Tailscale)
Documentation=https://github.com/tetrixdev/engram-agent

[Service]
Type=oneshot
ExecStart=/usr/local/bin/engram-agent snapshot
User=root
UMask=0027
TimeoutStartSec=60

# Hardening: it reads, and writes only /var/lib/engram-agent-snapshot.
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/engram-agent-snapshot
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
# The firewall is read over netlink (iptables-legacy opens a raw AF_INET
# socket); IPAddressDeny keeps every packet off the network. Not
# PrivateNetwork: that would read an empty namespace's firewall.
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
IPAddressDeny=any
SocketBindDeny=any
# Root, but only these: reading the netfilter tables, and reading users'
# authorized_keys in home directories it does not own.
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH
AmbientCapabilities=

MemoryMax=128M
Nice=10
SNAPSERVICE
		else
			cat >"$tmpu" <<'SNAPTIMER'
# Starts engram-agent-snapshot.service a minute after boot and every 5
# minutes after it last ran. Installed by packaging/install.sh.
[Unit]
Description=Engram server agent: root snapshot every 5 minutes
Documentation=https://github.com/tetrixdev/engram-agent

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
SNAPTIMER
		fi
		if ! cmp -s "$tmpu" "/etc/systemd/system/$f" 2>/dev/null; then
			install -m 0644 "$tmpu" "/etc/systemd/system/$f"
			snap_changed=1
		fi
		rm -f "$tmpu"
	done
else
	say "this binary has no snapshot command; the root snapshot is not installed"
fi

# Enrol, as the agent's own user, so the key it makes is its own.
if [ -n "$url" ] || [ -n "$code" ]; then
	[ -n "$url" ] && [ -n "$code" ] || die "enrolling needs both --url and --code"
	if [ -e "$STATE/identity.json" ]; then
		say "already enrolled ($STATE/identity.json); remove the server in the Servers app and delete that file to enrol again"
	else
		runuser -u "$USER_NAME" -- "$BIN_DST" enrol --url "$url" --code "$code"
	fi
fi

if has_systemd; then
	systemctl daemon-reload
	if [ "$snap" = 1 ]; then
		# One snapshot now, so the agent finds it at once; then every 5 minutes.
		if [ "$changed" = 1 ] || [ "$snap_changed" = 1 ] || [ ! -e "$SNAP_DIR/state.json" ]; then
			systemctl start engram-agent-snapshot.service ||
				say "the snapshot failed; see journalctl -u engram-agent-snapshot"
		fi
		systemctl enable --now engram-agent-snapshot.timer >/dev/null 2>&1
	fi
	systemctl enable engram-agent.service >/dev/null 2>&1
	if [ "$changed" = 1 ] || ! systemctl is-active --quiet engram-agent.service; then
		systemctl restart engram-agent.service
	fi
	say "running: systemctl status engram-agent engram-agent-snapshot.timer; engram-agent status"
else
	say "installed; this system does not run systemd, so start it yourself: runuser -u $USER_NAME -- $BIN_DST run"
fi
