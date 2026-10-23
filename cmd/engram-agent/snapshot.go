package main

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tetrixdev/engram-agent/internal/snapshot"
)

// cmdSnapshot is the root oneshot the snapshot timer starts: it reads what
// the unprivileged agent cannot and writes it into one file. It takes no
// input and opens no network connection.
func cmdSnapshot(args []string, out, errOut io.Writer) error {
	fs := newFlags("snapshot", errOut)
	dir := fs.String("out", snapshot.DefaultDir, "the directory to write "+snapshot.FileName+" into")
	asJSON := fs.Bool("json", false, "print the snapshot on stdout instead of writing it")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	d := snapshot.DefaultEnv().Collect(ctx, Version)
	if *asJSON {
		return writeJSON(out, d)
	}
	if err := snapshot.Write(*dir, d, nil); err != nil {
		return err
	}
	// One line for the journal: how much each section held, and what failed.
	var parts []string
	names := append([]string(nil), snapshot.SectionNames...)
	sort.Strings(names)
	for _, n := range names {
		s := d.Sections[n]
		p := fmt.Sprintf("%s %d", n, count(s.Items))
		if s.Error != nil {
			p += " (error: " + *s.Error + ")"
		}
		parts = append(parts, p)
	}
	fmt.Fprintf(errOut, "engram-agent snapshot: wrote %s: %s\n", filepath.Join(*dir, snapshot.FileName), strings.Join(parts, ", "))
	return nil
}

func count(items any) int {
	switch v := items.(type) {
	case []snapshot.Rule:
		return len(v)
	case []snapshot.Container:
		return len(v)
	case []snapshot.User:
		return len(v)
	case []snapshot.Key:
		return len(v)
	case []snapshot.Tailnet:
		return len(v)
	}
	return 0
}
