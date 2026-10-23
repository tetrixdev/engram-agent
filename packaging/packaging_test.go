// Package packaging holds the systemd units and the installer; this test
// keeps the units embedded in install.sh identical to the files, and checks
// the hardening each unit must keep.
package packaging

import (
	"os"
	"strings"
	"testing"
)

// embedded is the text between `<<'MARK'` and the line MARK in install.sh.
func embedded(t *testing.T, sh, mark string) string {
	t.Helper()
	open := "<<'" + mark + "'\n"
	start := strings.Index(sh, open)
	if start < 0 {
		t.Fatalf("no embedded %s in install.sh", mark)
	}
	rest := sh[start+len(open):]
	end := strings.Index(rest, "\n"+mark+"\n")
	if end < 0 {
		t.Fatalf("the embedded %s in install.sh does not end", mark)
	}
	return rest[:end+1]
}

func TestEmbeddedUnitsMatchFiles(t *testing.T) {
	b, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	sh := string(b)
	units := map[string]string{
		"engram-agent.service":          "UNIT",
		"engram-agent-snapshot.service": "SNAPSERVICE",
		"engram-agent-snapshot.timer":   "SNAPTIMER",
	}
	for file, mark := range units {
		u, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if embedded(t, sh, mark) != string(u) {
			t.Errorf("the %s embedded in install.sh differs from %s: copy the file into the heredoc", mark, file)
		}
	}
}

func lacks(t *testing.T, file string, want []string) {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range want {
		if !strings.Contains(string(b), "\n"+w+"\n") {
			t.Errorf("%s lacks %s", file, w)
		}
	}
}

func TestAgentUnitHardening(t *testing.T) {
	lacks(t, "engram-agent.service", []string{"User=engram-agent", "NoNewPrivileges=yes", "ProtectSystem=strict", "ReadWritePaths=/var/lib/engram-agent",
		"ProtectHome=read-only", "PrivateTmp=yes", "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK", "SupplementaryGroups=systemd-journal adm",
		"CapabilityBoundingSet=", "SocketBindDeny=any"})
}

func TestSnapshotUnitHardening(t *testing.T) {
	lacks(t, "engram-agent-snapshot.service", []string{"Type=oneshot", "ExecStart=/usr/local/bin/engram-agent snapshot", "User=root",
		"NoNewPrivileges=yes", "ProtectSystem=strict", "ReadWritePaths=/var/lib/engram-agent-snapshot", "ProtectHome=read-only",
		"PrivateTmp=yes", "PrivateDevices=yes", "IPAddressDeny=any", "RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6",
		"CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH", "MemoryMax=128M", "TimeoutStartSec=60", "Nice=10"})
	b, _ := os.ReadFile("engram-agent-snapshot.service")
	if strings.Contains(string(b), "PrivateNetwork=") {
		t.Error("PrivateNetwork would read an empty namespace's firewall")
	}
	lacks(t, "engram-agent-snapshot.timer", []string{"OnBootSec=1min", "OnUnitActiveSec=5min", "WantedBy=timers.target"})
}

func TestInstallerHandlesTheSnapshot(t *testing.T) {
	b, _ := os.ReadFile("install.sh")
	sh := string(b)
	for _, want := range []string{
		`install -d -m 2750 -o root -g "$USER_NAME" "$SNAP_DIR"`,
		"systemctl enable --now engram-agent-snapshot.timer",
		"systemctl disable --now engram-agent-snapshot.timer",
		`rm -f "$UNIT_DST" "$SNAP_SERVICE_DST" "$SNAP_TIMER_DST" "$BIN_DST"`,
		`rm -rf "$STATE" "$SNAP_DIR" "$CONF_DIR"`,
		"SNAP_DIR=/var/lib/engram-agent-snapshot",
	} {
		if !strings.Contains(sh, want) {
			t.Errorf("install.sh lacks %s", want)
		}
	}
}
