package snapshot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// Container is one container as the Docker Engine API lists it.
type Container struct {
	Name           string   `json:"name"`     // without the leading /
	Image          string   `json:"image"`    // as configured, e.g. ghcr.io/x/y:1.4.0
	ImageID        string   `json:"image_id"` // sha256:...
	State          string   `json:"state"`    // running, exited, ...
	ComposeProject *string  `json:"compose_project"`
	ComposeService *string  `json:"compose_service"`
	Published      []string `json:"published"` // "0.0.0.0:443->443/tcp", "[::]:443->443/tcp"; only ports with a public port
}

// apiContainer is the part of GET /containers/json the snapshot uses.
type apiContainer struct {
	Names   []string
	Image   string
	ImageID string
	State   string
	Labels  map[string]string
	Ports   []struct {
		IP          string
		PrivatePort int
		PublicPort  int
		Type        string
	}
}

// Containers asks the Docker Engine over its unix socket (plain HTTP, no
// docker CLI) for every container, running or not.
func (e Env) Containers(ctx context.Context) Section {
	sock := e.socket()
	if _, err := os.Stat(sock); errors.Is(err, fs.ErrNotExist) {
		return Section{Items: []Container{}, Meta: map[string]any{"docker": false}}
	}
	cl := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
		DisableKeepAlives: true,
	}}
	list, err := listContainers(ctx, cl)
	if err != nil {
		return Section{Items: []Container{}, Meta: map[string]any{"docker": true}, Error: errp(fmt.Errorf("docker socket %s: %w", sock, err))}
	}
	return Section{Items: list, Meta: map[string]any{"docker": true}}
}

func listContainers(ctx context.Context, cl *http.Client) ([]Container, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/v1.41/containers/json?all=1", nil)
	if err != nil {
		return nil, err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /v1.41/containers/json answered %d: %s", resp.StatusCode, firstLineOf(string(body)))
	}
	var raw []apiContainer
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("GET /v1.41/containers/json: %w", err)
	}
	out := make([]Container, 0, len(raw))
	for _, c := range raw {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		ct := Container{Name: name, Image: c.Image, ImageID: c.ImageID, State: c.State, Published: []string{}}
		if p, ok := c.Labels["com.docker.compose.project"]; ok {
			ct.ComposeProject = &p
		}
		if s, ok := c.Labels["com.docker.compose.service"]; ok {
			ct.ComposeService = &s
		}
		seen := map[string]bool{}
		for _, p := range c.Ports {
			if p.PublicPort == 0 {
				continue
			}
			ip := p.IP
			if ip == "" {
				ip = "0.0.0.0"
			}
			if strings.Contains(ip, ":") {
				ip = "[" + ip + "]"
			}
			s := fmt.Sprintf("%s:%d->%d/%s", ip, p.PublicPort, p.PrivatePort, p.Type)
			if !seen[s] {
				seen[s] = true
				ct.Published = append(ct.Published, s)
			}
		}
		sort.Strings(ct.Published)
		out = append(out, ct)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
