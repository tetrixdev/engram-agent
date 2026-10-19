package main

import (
	"context"
	"io"
	"log"
	"os/signal"
	"syscall"
	"time"

	"github.com/tetrixdev/engram/agent/internal/collect"
	"github.com/tetrixdev/engram/agent/internal/config"
	"github.com/tetrixdev/engram/agent/internal/store"
)

// Interval is how often the collector samples.
const Interval = 10 * time.Second

func enrolmentOf(cfg *config.Config) Enrolment {
	return Enrolment{Note: "this version collects history only; reporting to Engram is not built yet"}
}

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
	return run(ctx, cfg, *interval, *samples, log.New(errOut, "", 0))
}

// run is the service: sample every interval, store, and maintain the store
// once a minute.
func run(ctx context.Context, cfg *config.Config, interval time.Duration, samples int, lg *log.Logger) error {
	s, err := store.Open(cfg.DB)
	if err != nil {
		return err
	}
	defer s.Close()
	s.MaxBytes = cfg.MaxBytes()
	col := collect.New(cfg.Paths())
	lg.Printf("engram-agent %s: sampling every %s into %s (cap %d MB)", Version, interval, cfg.DB, cfg.MaxBytes()>>20)

	step := int64(interval / time.Second)
	if step <= 0 {
		step = 1
	}
	lastMaintain := int64(0)
	taken := 0
	for {
		// Wait for the next aligned moment, so samples sit on round times.
		n := time.Now()
		next := n.Truncate(interval).Add(interval)
		select {
		case <-ctx.Done():
			lg.Printf("stopping")
			return nil
		case <-time.After(next.Sub(n)):
		}
		smp := col.Collect()
		t := smp.T.Unix()
		t -= t % step
		if err := s.Write(t, smp.Values, smp.TopCPU, smp.TopMem); err != nil {
			lg.Printf("write sample: %v", err)
		}
		taken++
		if t/60 != lastMaintain/60 || (samples > 0 && taken >= samples) {
			if err := s.Maintain(smp.T); err != nil {
				lg.Printf("maintain: %v", err)
			}
			lastMaintain = t
		}
		if samples > 0 && taken >= samples {
			return nil
		}
	}
}
