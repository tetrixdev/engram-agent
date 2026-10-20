package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/tetrixdev/engram-agent/internal/inventory"
	"github.com/tetrixdev/engram-agent/internal/logs"
)

func cmdInventory(args []string, out, errOut io.Writer) error {
	fs := newFlags("inventory", errOut)
	c := commonFlags(fs)
	section := fs.String("section", "summary", "one of "+strings.Join(inventory.Sections, ", "))
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	cfg, err := c.load()
	if err != nil {
		return c.wrap(err)
	}
	env := inventory.DefaultEnv()
	env.Root, env.Proc, env.Cgroup = cfg.Root, cfg.Proc, cfg.Cgroup
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	v, err := inventorySection(ctx, env, *section)
	if err != nil {
		return c.wrap(err)
	}
	if *c.json {
		return writeJSON(out, v)
	}
	printInventory(out, *section, v)
	return nil
}

func inventorySection(ctx context.Context, env inventory.Env, section string) (any, error) {
	switch section {
	case "summary":
		f := env.Collect(ctx, Version, true)
		return map[string]any{"summary": f.Summary, "errors": nonNil(f.Errors)}, nil
	case "os":
		return map[string]any{"os": env.OSRelease(), "hostname": env.Hostname(), "arch": inventory.Arch(), "boot_time": env.BootTime()}, nil
	case "kernel":
		pkgs, err := env.Packages()
		if err != nil {
			return nil, err
		}
		k := env.Kernel(pkgs)
		reboot, rp := env.Reboot()
		return map[string]any{"kernel": k, "reboot_required": reboot, "reboot_packages": rp}, nil
	case "packages":
		pkgs, err := env.Packages()
		if err != nil {
			return nil, err
		}
		n, sum := inventory.PackagesDigest(pkgs)
		if pkgs == nil {
			pkgs = []inventory.Package{}
		}
		return map[string]any{"count": n, "sha256": sum, "packages": pkgs}, nil
	case "updates":
		pkgs, _ := env.Packages()
		u := env.Updates(ctx)
		return map[string]any{"updates": u, "unattended_upgrades": env.UnattendedUpgrades(pkgs)}, nil
	case "services":
		failed, err := env.FailedUnits(ctx)
		res := map[string]any{"failed_units": failed}
		if err != nil {
			res["error"] = err.Error()
		}
		return res, nil
	case "ports":
		ports := env.Ports()
		if ports == nil {
			ports = []inventory.Port{}
		}
		return map[string]any{"ports": ports, "listening": inventory.Listening(ports), "note": "process names need root and are not read"}, nil
	case "users":
		return map[string]any{"login_users": env.LoginUsers()}, nil
	case "ssh":
		return map[string]any{"ssh": env.SSHD(), "host_keys": env.SSHHostKeys()}, nil
	case "containers":
		return map[string]any{"containers": env.Containers(), "note": "running containers by short id, from their cgroups; names need the docker socket"}, nil
	}
	return nil, fmt.Errorf("unknown section %q: one of %s", section, strings.Join(inventory.Sections, ", "))
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// printInventory is the human form: the JSON, which reads well enough for
// every section and keeps one shape to maintain.
func printInventory(out io.Writer, _ string, v any) { _ = writeJSON(out, v) }

func cmdLogs(args []string, out, errOut io.Writer) error {
	fs := newFlags("logs", errOut)
	c := commonFlags(fs)
	unit := fs.String("unit", "", "a systemd unit, e.g. nginx.service")
	container := fs.String("container", "", "a docker container name or id")
	file := fs.String("file", "", "a file under /var/log (the configuration's log_files)")
	lines := fs.Int("lines", 100, fmt.Sprintf("how many lines, at most %d", logs.MaxLines))
	since := fs.String("since", "", "only lines since then (unit and container): \"2026-10-19 14:00\" or 1h")
	grep := fs.String("grep", "", "only lines containing this text")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	cfg, err := c.load()
	if err != nil {
		return c.wrap(err)
	}
	if *unit == "" && *container == "" && *file == "" {
		return c.wrap(errors.New("give one of --unit, --container or --file"))
	}
	res, err := logs.Read(context.Background(), logs.Request{Unit: *unit, Container: *container, File: *file,
		Lines: *lines, Since: *since, Grep: *grep, Allowed: cfg.LogFiles})
	if err != nil {
		return c.wrap(err)
	}
	if *c.json {
		return writeJSON(out, res)
	}
	for _, l := range res.Lines {
		fmt.Fprintln(out, l)
	}
	if res.Note != "" {
		fmt.Fprintln(errOut, res.Note)
	}
	if res.Masked > 0 || res.Truncated {
		fmt.Fprintf(errOut, "(%d masked, truncated: %v)\n", res.Masked, res.Truncated)
	}
	return nil
}
