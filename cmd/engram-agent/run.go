package main

import (
	"context"
	"io"
	"log"
	"os/signal"
	"syscall"
	"time"

	"github.com/tetrixdev/engram-agent/internal/agent"
	"github.com/tetrixdev/engram-agent/internal/store"
)

// Interval is how often the collector samples.
const Interval = 10 * time.Second

func cmdRun(args []string, out, errOut io.Writer) error {
	fs := newFlags("run", errOut)
	c := commonFlags(fs)
	samples := fs.Int("samples", 0, "stop after this many samples (0: run until stopped); for tests")
	interval := fs.Duration("interval", Interval, "sampling interval")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	cfg, err := c.load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	lg := log.New(errOut, "", 0)
	s, err := store.Open(cfg.DB)
	if err != nil {
		return err
	}
	defer s.Close()
	s.MaxBytes = cfg.MaxBytes()
	a, err := agent.New(cfg, s, Version, lg)
	if err != nil {
		return err
	}
	a.Interval = *interval
	lg.Printf("engram-agent %s: sampling every %s into %s (cap %d MB)", Version, *interval, cfg.DB, cfg.MaxBytes()>>20)
	return a.Run(ctx, *samples)
}
