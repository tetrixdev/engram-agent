// Command engram-agent collects a server's health into a local history and
// answers questions about it. See agent/README.md.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// Version is set at build time (-ldflags "-X main.Version=...").
var Version = "0.1.0"

func main() {
	os.Exit(Main(os.Args[1:], os.Stdout, os.Stderr))
}

type command struct {
	name, usage string
	run         func(args []string, out, errOut io.Writer) error
}

var commands []command

func init() {
	commands = []command{
		{"run", "run the collector (the systemd service)", cmdRun},
		{"status", "what the host looks like now, the last hour's peaks, enrolment", cmdStatus},
		{"peaks", "the highest peaks per metric in a range", cmdPeaks},
		{"top", "the top processes by cpu and memory at a moment", cmdTop},
		{"query", "one metric over a range, as JSON: query --json '{\"metric\":...}'", cmdQuery},
		{"metrics", "the metric names this host records", cmdMetrics},
		{"inventory", "what is on this server: --section summary|os|kernel|packages|updates|services|ports|users|ssh|containers", cmdInventory},
		{"logs", "recent log lines, masked: --unit X | --container X | --file /var/log/...", cmdLogs},
		{"enrol", "enrol with Engram: --url <origin> --code <code>", cmdEnrol},
		{"version", "print the version", func(_ []string, out, _ io.Writer) error {
			fmt.Fprintln(out, Version)
			return nil
		}},
	}
}

// Main runs one command and returns the exit code.
func Main(args []string, out, errOut io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		usage(errOut)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	for _, c := range commands {
		if c.name == args[0] {
			if err := c.run(args[1:], out, errOut); err != nil {
				if errors.Is(err, flag.ErrHelp) {
					return 0
				}
				var je jsonErr
				if errors.As(err, &je) {
					// A --json caller gets the error as JSON on stdout too.
					enc := json.NewEncoder(out)
					_ = enc.Encode(map[string]string{"error": je.err.Error()})
					err = je.err
				}
				fmt.Fprintln(errOut, "engram-agent "+c.name+": "+err.Error())
				return 1
			}
			return 0
		}
	}
	fmt.Fprintf(errOut, "engram-agent: unknown command %q\n\n", args[0])
	usage(errOut)
	return 2
}

type jsonErr struct{ err error }

func (j jsonErr) Error() string { return j.err.Error() }

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: engram-agent <command> [flags]")
	fmt.Fprintln(w)
	for _, c := range commands {
		fmt.Fprintf(w, "  %-9s %s\n", c.name, c.usage)
	}
	fmt.Fprintln(w, "\nEvery read command takes --json. `engram-agent <command> -h` lists its flags.")
}

// parseArgs parses flags that may come before or after positional arguments.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func writeJSON(out io.Writer, v any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func newFlags(name string, errOut io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("engram-agent "+name, flag.ContinueOnError)
	fs.SetOutput(errOut)
	return fs
}

func trimFloat(f float64) string {
	s := fmt.Sprintf("%.2f", f)
	s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	if s == "-0" {
		return "0"
	}
	return s
}
