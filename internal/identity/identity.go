// Package identity is the agent's key pair, its enrolment with Engram, and
// the signature every report carries (wire protocol v1).
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Files in the state directory.
const (
	KeyFile      = "agent.key"
	IdentityFile = "identity.json"
)

// Identity is what enrolment leaves behind (identity.json).
type Identity struct {
	URL          string    `json:"url"`
	AgentID      string    `json:"agent_id"`
	Fingerprint  string    `json:"fingerprint"`
	ReportEveryS int       `json:"report_every_s,omitempty"`
	EnrolledAt   time.Time `json:"enrolled_at"`
}

// Fingerprint is how a person compares a key: the first 10 bytes of the
// sha256 of the raw 32-byte public key, base32 (RFC 4648, uppercase, no
// padding: 16 characters), in four groups of four, e.g. ABCD-EFGH-IJKL-MNOP.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	s := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:10])
	return s[0:4] + "-" + s[4:8] + "-" + s[8:12] + "-" + s[12:16]
}

// SignedString is the exact bytes a report's signature covers.
func SignedString(agentID string, unix int64, body []byte) []byte {
	sum := sha256.Sum256(body)
	return []byte("engram-agent-v1\n" + agentID + "\n" + fmt.Sprint(unix) + "\n" + hex.EncodeToString(sum[:]))
}

// Sign is the X-Engram-Signature header value: base64 (standard, padded) of
// the ed25519 signature over SignedString.
func Sign(key ed25519.PrivateKey, agentID string, unix int64, body []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, SignedString(agentID, unix, body)))
}

// LoadOrCreateKey reads the private key from dir, making a new pair (file
// 0600) when there is none.
func LoadOrCreateKey(dir string) (ed25519.PrivateKey, error) {
	k, err := LoadKey(dir)
	if err == nil {
		return k, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := writeAtomic(filepath.Join(dir, KeyFile), b, 0o600); err != nil {
		return nil, err
	}
	return priv, nil
}

// LoadKey reads the private key (PKCS #8 PEM).
func LoadKey(dir string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(filepath.Join(dir, KeyFile))
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s is not a PEM key", filepath.Join(dir, KeyFile))
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an ed25519 key", filepath.Join(dir, KeyFile))
	}
	return priv, nil
}

// Load reads identity.json; fs.ErrNotExist when the agent is not enrolled.
func Load(dir string) (*Identity, error) {
	b, err := os.ReadFile(filepath.Join(dir, IdentityFile))
	if err != nil {
		return nil, err
	}
	var id Identity
	if err := json.Unmarshal(b, &id); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Join(dir, IdentityFile), err)
	}
	if id.AgentID == "" || id.URL == "" {
		return nil, fmt.Errorf("%s lacks url or agent_id", filepath.Join(dir, IdentityFile))
	}
	return &id, nil
}

// Save writes identity.json (0640: the group may read who the agent is).
func Save(dir string, id *Identity) error {
	b, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, IdentityFile), append(b, '\n'), 0o640)
}

func writeAtomic(path string, b []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// NormalizeURL checks an Engram origin: https, or http only to this machine
// (tests, a local Engram). It returns the origin without a trailing slash.
func NormalizeURL(raw string) (string, error) {
	u := strings.TrimRight(strings.TrimSpace(raw), "/")
	switch {
	case strings.HasPrefix(u, "https://"):
	case strings.HasPrefix(u, "http://localhost"), strings.HasPrefix(u, "http://127.0.0.1"), strings.HasPrefix(u, "http://[::1]"):
	default:
		return "", fmt.Errorf("the Engram address must start with https:// (got %q)", raw)
	}
	if strings.ContainsAny(u[8:], "?#") {
		return "", fmt.Errorf("give the Engram origin only, e.g. https://engram.example.org (got %q)", raw)
	}
	return u, nil
}
