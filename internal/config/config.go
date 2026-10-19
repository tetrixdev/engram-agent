// Package config reads the agent's optional configuration file.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/tetrixdev/engram/agent/internal/collect"
)

// DefaultPath is where the service looks for its configuration. The file is
// optional: without it every default holds.
const DefaultPath = "/etc/engram-agent/config.json"

// DefaultStateDir holds the history, the identity and the key.
const DefaultStateDir = "/var/lib/engram-agent"

// Config is the whole file. Every key is optional.
type Config struct {
	// StateDir holds history.db, identity.json and agent.key.
	StateDir string `json:"state_dir"`
	// DB is the history file; default <state_dir>/history.db.
	DB string `json:"db"`
	// MaxDBMB is the size cap of the history in MB; default 500. 0 keeps the default; -1 turns the cap off.
	MaxDBMB int64 `json:"max_db_mb"`
	// Paths are the roots read; tests and containers change them.
	Proc   string `json:"proc"`
	Sys    string `json:"sys"`
	Cgroup string `json:"cgroup"`
	// Root is the host's filesystem root for the files the inventory reads
	// (/etc/os-release, /var/lib/dpkg/status, ...); default "/".
	Root string `json:"root"`
}

// Load reads path; a missing file is the defaults, a broken one an error.
func Load(path string) (*Config, error) {
	c := &Config{}
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if err == nil {
		if err := json.Unmarshal(b, c); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	c.fill()
	return c, nil
}

func (c *Config) fill() {
	d := collect.DefaultPaths()
	if c.StateDir == "" {
		c.StateDir = DefaultStateDir
	}
	if c.DB == "" {
		c.DB = filepath.Join(c.StateDir, "history.db")
	}
	if c.MaxDBMB == 0 {
		c.MaxDBMB = 500
	}
	if c.Proc == "" {
		c.Proc = d.Proc
	}
	if c.Sys == "" {
		c.Sys = d.Sys
	}
	if c.Cgroup == "" {
		c.Cgroup = d.Cgroup
	}
	if c.Root == "" {
		c.Root = "/"
	}
}

// Paths are the collector's roots.
func (c *Config) Paths() collect.Paths {
	return collect.Paths{Proc: c.Proc, Sys: c.Sys, Cgroup: c.Cgroup}
}

// MaxBytes is the size cap in bytes (0: none).
func (c *Config) MaxBytes() int64 {
	if c.MaxDBMB < 0 {
		return 0
	}
	return c.MaxDBMB << 20
}
