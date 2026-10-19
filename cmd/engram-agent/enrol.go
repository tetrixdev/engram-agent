package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/tetrixdev/engram/agent/internal/config"
	"github.com/tetrixdev/engram/agent/internal/identity"
	"github.com/tetrixdev/engram/agent/internal/inventory"
	"github.com/tetrixdev/engram/agent/internal/report"
)

func cmdEnrol(args []string, out, errOut io.Writer) error {
	fs := newFlags("enrol", errOut)
	c := commonFlags(fs)
	url := fs.String("url", "", "the Engram origin, e.g. https://engram.example.org")
	code := fs.String("code", "", "the one-time code from the Servers app")
	force := fs.Bool("force", false, "enrol again although this agent is enrolled (the old enrolment is forgotten here; remove it in the Servers app)")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	if *url == "" || *code == "" {
		return errors.New("give --url and --code: the Engram address and the code the Servers app shows")
	}
	origin, err := identity.NormalizeURL(*url)
	if err != nil {
		return err
	}
	cfg, err := c.load()
	if err != nil {
		return err
	}
	if id, err := identity.Load(cfg.StateDir); err == nil && !*force {
		return fmt.Errorf("already enrolled with %s as %s (fingerprint %s); --force enrols again", id.URL, id.AgentID, id.Fingerprint)
	}
	key, err := identity.LoadOrCreateKey(cfg.StateDir)
	if err != nil {
		return fmt.Errorf("make the key in %s: %w (run as the engram-agent user: runuser -u engram-agent -- engram-agent enrol ...)", cfg.StateDir, err)
	}
	env := inventory.DefaultEnv()
	env.Root, env.Proc = cfg.Root, cfg.Proc
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cl := report.NewClient(Version)
	res, err := cl.Enrol(ctx, origin, report.EnrolRequest{
		Code: *code, PublicKey: report.PublicKeyB64(key), Hostname: env.Hostname(),
		AgentVersion: Version, OS: env.OSRelease(), Arch: inventory.Arch(),
	})
	if err != nil {
		return err
	}
	fp := identity.Fingerprint(key.Public().(ed25519.PublicKey))
	if res.Fingerprint != "" && res.Fingerprint != fp {
		// Engram computed a different fingerprint of the key it received: the
		// key was changed on the way. Do not keep this enrolment.
		return fmt.Errorf("Engram reports fingerprint %s for this agent's key, which is %s here: not enrolled; check what sits between this server and Engram", res.Fingerprint, fp)
	}
	id := &identity.Identity{URL: origin, AgentID: res.AgentID, Fingerprint: fp, ReportEveryS: res.ReportEveryS, EnrolledAt: time.Now().UTC().Truncate(time.Second)}
	if err := identity.Save(cfg.StateDir, id); err != nil {
		return err
	}
	fmt.Fprintf(out, "enrolled with %s as %s\nfingerprint %s\ncompare it with the one the Servers app shows for this server\n", origin, id.AgentID, fp)
	return nil
}

func enrolmentOf(cfg *config.Config, meta func(string) string) Enrolment {
	id, err := identity.Load(cfg.StateDir)
	if err != nil {
		e := Enrolment{Note: "not enrolled: engram-agent enrol --url <Engram> --code <code from the Servers app>"}
		if !os.IsNotExist(err) {
			e.Note = err.Error()
		}
		return e
	}
	e := Enrolment{Enrolled: true, URL: id.URL, AgentID: id.AgentID, Fingerprint: id.Fingerprint}
	if meta != nil {
		e.Report = meta("report.state")
		e.LastReport = meta("report.last_ok")
		if e.Report != report.StateOK {
			e.Note = meta("report.detail")
		}
	}
	return e
}
