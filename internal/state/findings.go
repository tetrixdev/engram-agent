package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/tetrixdev/engram-agent/internal/inventory"
)

// ReasonComment is what a firewall rule's comment must look like: a key, a
// colon, a space, and at least 20 characters saying why the rule exists.
var ReasonComment = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,40}: .{20,}$`)

// judgedChains are the chains whose rules a person writes (Docker's and
// Tailscale's own chains are theirs).
var judgedChains = map[string]bool{"INPUT": true, "FORWARD": true, "OUTPUT": true, "DOCKER-USER": true}

// FirewallRule is a firewall item of the snapshot.
type FirewallRule struct {
	Family  string  `json:"family"`
	Chain   string  `json:"chain"`
	Rule    string  `json:"rule"`
	Comment *string `json:"comment"`
	Target  *string `json:"target"`
}

// Uncommented lists the rules that need a reason and lack one: in INPUT,
// FORWARD, OUTPUT or DOCKER-USER, not a jump to a chain named DOCKER* or
// ts-*, with a comment missing or not shaped like ReasonComment.
func Uncommented(items []json.RawMessage) []FirewallRule {
	var out []FirewallRule
	for _, it := range items {
		var r FirewallRule
		if json.Unmarshal(it, &r) != nil || !judgedChains[r.Chain] {
			continue
		}
		if r.Target != nil && (strings.HasPrefix(*r.Target, "DOCKER") || strings.HasPrefix(*r.Target, "ts-")) {
			continue
		}
		if r.Comment != nil && ReasonComment.MatchString(*r.Comment) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// FirewallFindingPrefix starts the key of every firewall_rule_uncommented finding.
const FirewallFindingPrefix = "firewall_uncommented:"

// FirewallFindings are the firewall_rule_uncommented findings, by key.
func FirewallFindings(rules []FirewallRule) map[string]inventory.Finding {
	out := map[string]inventory.Finding{}
	for _, r := range rules {
		sum := sha256.Sum256([]byte(r.Rule))
		key := fmt.Sprintf("%s%s:%s:%s", FirewallFindingPrefix, r.Family, r.Chain, hex.EncodeToString(sum[:])[:12])
		subject := r.Rule
		fam := "iptables"
		if r.Family == "v6" {
			fam = "ip6tables"
		}
		detail := fmt.Sprintf("This %s rule in %s says nothing about why it is there. Give it a reason as a comment match: "+
			"-m comment --comment \"<key>: <why, 20+ characters>\", e.g. -m comment --comment \"web: the proxy serves the sites; 80 for ACME\". "+
			"The key is lowercase letters, digits, _ . or -, at most 41 characters.", fam, r.Chain)
		out[key] = inventory.Finding{Kind: "firewall_rule_uncommented", Category: "security", Severity: "high",
			Title: clip("Firewall rule without a reason: "+r.Chain+" "+r.Rule, 200), Detail: &detail, Subject: &subject}
	}
	return out
}

// clip cuts s to at most n characters.
func clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

// SnapshotNotRunning is the snapshot_not_running finding.
func SnapshotNotRunning(status string, err *string) inventory.Finding {
	d := "The root snapshot (engram-agent-snapshot.timer, every 5 minutes) has not written a fresh /var/lib/engram-agent-snapshot/state.json for over 30 minutes " +
		"(status " + status + "), so the firewall, containers, users, SSH keys and Tailscale Engram shows are the last ones it sent. " +
		"Check it with: systemctl status engram-agent-snapshot.timer engram-agent-snapshot.service"
	if err != nil {
		d += ". The agent read: " + *err
	}
	return inventory.Finding{Kind: "snapshot_not_running", Category: "maintenance", Severity: "medium",
		Title: "The root snapshot is not running", Detail: &d}
}
