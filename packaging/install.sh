#!/bin/sh
# Install, update or remove engram-agent on this server. Run as root.
#
#   install.sh --binary ./engram-agent [--sha256 HEX] [--ssh-user NAME]... [--url ORIGIN --code CODE]
#   install.sh --binary https://.../engram-agent-linux-amd64 --sha256 HEX ...
#   install.sh --uninstall [--purge]
#
# --binary    the engram-agent binary: a local path, or an https URL (then
#             --sha256 is required). Leave it out to keep the installed one.
# --sha256    the binary's expected sha256; the install stops on a mismatch.
# --ssh-user  a login that may run the read commands (status, query, ...):
#             added to group engram-agent. Repeatable.
# --url/--code  enrol with Engram: the origin and the one-time code from the
#             Servers app. Needs a binary that has `engram-agent enrol`.
# --uninstall stop and remove the service and the binary; the history, the
#             identity and the user stay, unless --purge is also given.
#
# Running it again is safe: it converges on the same result.
set -eu

BIN_DST=/usr/local/bin/engram-agent
UNIT_DST=/etc/systemd/system/engram-agent.service
STATE=/var/lib/engram-agent
CONF_DIR=/etc/engram-agent
USER_NAME=engram-agent

binary="" sha="" url="" code="" uninstall=0 purge=0 ssh_users=""

die() { echo "install.sh: $*" >&2; exit 1; }
say() { echo "engram-agent: $*"; }

while [ $# -gt 0 ]; do
	case "$1" in
	--binary) binary="${2:?--binary needs a path or URL}"; shift 2 ;;
	--sha256) sha="${2:?--sha256 needs a value}"; shift 2 ;;
	--ssh-user) ssh_users="$ssh_users ${2:?--ssh-user needs a name}"; shift 2 ;;
	--url) url="${2:?--url needs the Engram origin}"; shift 2 ;;
	--code) code="${2:?--code needs the enrolment code}"; shift 2 ;;
	--uninstall) uninstall=1; shift ;;
	--purge) purge=1; shift ;;
	-h|--help) sed -n '2,20p' "$0"; exit 0 ;;
	*) die "unknown argument $1 (--help lists them)" ;;
	esac
done

[ "$(id -u)" = 0 ] || die "run as root (sudo sh install.sh ...)"

has_systemd() { [ -d /run/systemd/system ]; }

if [ "$uninstall" = 1 ]; then
	if has_systemd; then
		systemctl disable --now engram-agent.service 2>/dev/null || true
	fi
	rm -f "$UNIT_DST" "$BIN_DST"
	has_systemd && systemctl daemon-reload || true
	if [ "$purge" = 1 ]; then
		rm -rf "$STATE" "$CONF_DIR"
		if id "$USER_NAME" >/dev/null 2>&1; then userdel "$USER_NAME" 2>/dev/null || true; fi
		if getent group "$USER_NAME" >/dev/null 2>&1; then groupdel "$USER_NAME" 2>/dev/null || true; fi
		say "removed, with its history, identity and user"
	else
		say "removed; history and identity kept in $STATE (--purge removes them and the user)"
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

# The binary.
changed=0
if [ -n "$binary" ]; then
	tmp=$(mktemp)
	trap 'rm -f "$tmp"' EXIT
	case "$binary" in
	https://*|http://*)
		[ -n "$sha" ] || die "a downloaded binary needs --sha256"
		if command -v curl >/dev/null 2>&1; then curl -fsSL --proto '=https' -o "$tmp" "$binary"
		elif command -v wget >/dev/null 2>&1; then wget -q -O "$tmp" "$binary"
		else die "neither curl nor wget is installed"; fi ;;
	*)
		[ -f "$binary" ] || die "--binary $binary: no such file"
		cp "$binary" "$tmp" ;;
	esac
	if [ -n "$sha" ]; then
		got=$(sha256sum "$tmp" | cut -d' ' -f1)
		[ "$got" = "$sha" ] || die "sha256 mismatch: expected $sha, got $got"
	fi
	chmod 0755 "$tmp"
	"$tmp" version >/dev/null 2>&1 || die "the binary does not run here (wrong architecture? this is $(uname -m))"
	if ! cmp -s "$tmp" "$BIN_DST" 2>/dev/null; then
		install -m 0755 -o root -g root "$tmp" "$BIN_DST"
		changed=1
		say "installed $("$BIN_DST" version) at $BIN_DST"
	fi
fi
[ -x "$BIN_DST" ] || die "no binary at $BIN_DST: give --binary"

# The unit: the copy beside this script, else the one embedded below (kept
# identical by agent/packaging/packaging_test.go). Groups this system lacks are
# left out of SupplementaryGroups, or systemd would refuse to start it.
here=$(dirname "$0")
unit=$(mktemp)
if [ -f "$here/engram-agent.service" ]; then
	cp "$here/engram-agent.service" "$unit"
else
	cat >"$unit" <<'UNIT'
# engram-agent: collects this server's health into /var/lib/engram-agent and
# (once enrolled) reports it to Engram. Unprivileged, read-only on the system,
# no listening socket. Installed by agent/packaging/install.sh.
[Unit]
Description=Engram server agent (health history, reports to Engram)
Documentation=https://github.com/tetrixdev/engram/tree/main/agent
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
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
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
	systemctl enable engram-agent.service >/dev/null 2>&1
	if [ "$changed" = 1 ] || ! systemctl is-active --quiet engram-agent.service; then
		systemctl restart engram-agent.service
	fi
	say "running: systemctl status engram-agent; engram-agent status"
else
	say "installed; this system does not run systemd, so start it yourself: runuser -u $USER_NAME -- $BIN_DST run"
fi
