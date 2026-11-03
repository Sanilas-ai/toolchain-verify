package dockerhost

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// engine is a GET-only client for the Docker/Podman Engine API on a local
// unix socket. It has no method that could create, start or modify anything.
type engine struct {
	socket string
	hc     *http.Client
}

func newEngine(socket string, timeout time.Duration) *engine {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		DisableKeepAlives: true,
	}
	return &engine{socket: socket, hc: &http.Client{Transport: tr, Timeout: timeout}}
}

const maxBody = 16 << 20

func (e *engine) get(path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, "http://engine"+path, nil)
	if err != nil {
		return err
	}
	resp, err := e.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", path, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(out)
}

// Engine API shapes (only the fields we read).
type apiInfo struct {
	ServerVersion   string   `json:"ServerVersion"`
	SecurityOptions []string `json:"SecurityOptions"`
	Name            string   `json:"Name"`
}

type apiContainerSummary struct {
	ID    string   `json:"Id"`
	Names []string `json:"Names"`
}

type apiPortBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

type apiMount struct {
	Type        string `json:"Type"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	RW          bool   `json:"RW"`
}

type apiContainer struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		Image  string            `json:"Image"`
		User   string            `json:"User"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	State struct {
		Running bool   `json:"Running"`
		Status  string `json:"Status"`
	} `json:"State"`
	HostConfig struct {
		Privileged   bool                        `json:"Privileged"`
		CapAdd       []string                    `json:"CapAdd"`
		SecurityOpt  []string                    `json:"SecurityOpt"`
		NetworkMode  string                      `json:"NetworkMode"`
		PidMode      string                      `json:"PidMode"`
		IpcMode      string                      `json:"IpcMode"`
		UsernsMode   string                      `json:"UsernsMode"`
		PortBindings map[string][]apiPortBinding `json:"PortBindings"`
		Devices      []struct {
			PathOnHost string `json:"PathOnHost"`
		} `json:"Devices"`
		ReadonlyRootfs bool `json:"ReadonlyRootfs"`
	} `json:"HostConfig"`
	Mounts          []apiMount `json:"Mounts"`
	NetworkSettings struct {
		Ports    map[string][]apiPortBinding `json:"Ports"`
		Networks map[string]json.RawMessage  `json:"Networks"`
	} `json:"NetworkSettings"`
}

type apiNetwork struct {
	Name     string `json:"Name"`
	Driver   string `json:"Driver"`
	Internal bool   `json:"Internal"`
}

// socketCandidates returns local engine sockets in preference order and,
// when DOCKER_HOST points somewhere remote, that value (never queried).
func socketCandidates(explicit string, getenv func(string) string) (socks []string, remote string) {
	if explicit != "" {
		return []string{explicit}, ""
	}
	if h := getenv("DOCKER_HOST"); h != "" {
		if u, err := url.Parse(h); err == nil && u.Scheme == "unix" {
			socks = append(socks, u.Path)
		} else {
			remote = h
		}
	}
	socks = append(socks, "/var/run/docker.sock", "/run/docker.sock")
	if x := getenv("XDG_RUNTIME_DIR"); x != "" {
		socks = append(socks, filepath.Join(x, "docker.sock"), filepath.Join(x, "podman", "podman.sock"))
	}
	socks = append(socks, "/run/podman/podman.sock")
	seen := map[string]bool{}
	var out []string
	for _, s := range socks {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out, remote
}

func isSocket(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode()&os.ModeSocket != 0
}

func containerName(c apiContainer, sum apiContainerSummary) string {
	n := strings.TrimPrefix(c.Name, "/")
	if n == "" && len(sum.Names) > 0 {
		n = strings.TrimPrefix(sum.Names[0], "/")
	}
	if n == "" && len(c.ID) >= 12 {
		n = c.ID[:12]
	}
	return n
}
