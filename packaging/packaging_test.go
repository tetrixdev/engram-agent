// Package packaging holds the systemd unit and the installer; this test keeps
// the unit embedded in install.sh identical to engram-agent.service.
package packaging

import (
	"os"
	"strings"
	"testing"
)

func TestEmbeddedUnitMatchesFile(t *testing.T) {
	unit, err := os.ReadFile("engram-agent.service")
	if err != nil {
		t.Fatal(err)
	}
	sh, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(sh)
	start := strings.Index(s, "<<'UNIT'\n")
	end := strings.Index(s, "\nUNIT\n")
	if start < 0 || end < start {
		t.Fatal("no embedded unit in install.sh")
	}
	embedded := s[start+len("<<'UNIT'\n") : end+1]
	if embedded != string(unit) {
		t.Fatal("the unit embedded in install.sh differs from engram-agent.service: copy the file into the heredoc")
	}
	for _, want := range []string{"User=engram-agent", "NoNewPrivileges=yes", "ProtectSystem=strict", "ReadWritePaths=/var/lib/engram-agent",
		"ProtectHome=read-only", "PrivateTmp=yes", "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX", "SupplementaryGroups=systemd-journal adm"} {
		if !strings.Contains(string(unit), "\n"+want+"\n") {
			t.Errorf("the unit lacks %s", want)
		}
	}
}
