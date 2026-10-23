package inventory

import (
	"sort"
	"strings"
)

// Finding is what the agent can judge about a server by itself. Its fields
// are the finding.opened state the Servers app declares.
type Finding struct {
	Kind     string  `json:"kind"`     // pending_reboot, failed_unit, ssh_password_auth, ssh_root_login, kernel_not_running_newest, firewall_rule_uncommented, snapshot_not_running
	Category string  `json:"category"` // security, maintenance
	Severity string  `json:"severity"` // info, low, medium, high, critical
	Title    string  `json:"title"`
	Detail   *string `json:"detail"`
	Since    string  `json:"since"`
	Subject  *string `json:"subject"`
}

func strp(s string) *string { return &s }

// Findings judges a summary. The key of each is the event ref: the kind,
// with ":<subject>" for those about one unit. since is filled by the caller
// (when it was first seen). Listening ports are not judged here: Engram
// compares them with what the server is declared to expose.
func Findings(s Summary) map[string]Finding {
	out := map[string]Finding{}
	if s.RebootRequired {
		f := Finding{Kind: "pending_reboot", Category: "maintenance", Severity: "medium", Title: "A reboot is required to finish installing updates"}
		if len(s.RebootPackages) > 0 {
			f.Detail = strp("Asked for by: " + strings.Join(s.RebootPackages, ", ") + ".")
		}
		out["pending_reboot"] = f
	}
	for _, u := range s.FailedUnits {
		out["failed_unit:"+u] = Finding{Kind: "failed_unit", Category: "maintenance", Severity: "medium",
			Title: "Systemd unit " + u + " has failed", Subject: strp(u)}
	}
	if s.SSH.PasswordAuth != nil && *s.SSH.PasswordAuth {
		out["ssh_password_auth"] = Finding{Kind: "ssh_password_auth", Category: "security", Severity: "medium",
			Title: "SSH accepts password logins", Detail: strp("PasswordAuthentication is yes (or not set, and OpenSSH's default is yes) in sshd's configuration files. Keys only is safer.")}
	}
	if s.SSH.RootLogin != nil && *s.SSH.RootLogin != "no" {
		v := *s.SSH.RootLogin
		f := Finding{Kind: "ssh_root_login", Category: "security", Severity: "low", Title: "SSH lets root log in with a key",
			Detail: strp("PermitRootLogin is " + v + ". Logging in as a user and using sudo leaves a trail per person.")}
		if v == "yes" {
			f.Severity, f.Title = "high", "SSH lets root log in with a password"
		}
		out["ssh_root_login"] = f
	}
	if s.KernelNewest != nil && s.Kernel != "" && *s.KernelNewest != s.Kernel {
		out["kernel_not_running_newest"] = Finding{Kind: "kernel_not_running_newest", Category: "maintenance", Severity: "low",
			Title:  "The running kernel is not the newest installed",
			Detail: strp("Running " + s.Kernel + ", newest installed " + *s.KernelNewest + ": a reboot loads it."), Subject: strp(*s.KernelNewest)}
	}
	return out
}

// Keys lists a finding map's keys, sorted.
func Keys(m map[string]Finding) []string {
	k := make([]string, 0, len(m))
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}
