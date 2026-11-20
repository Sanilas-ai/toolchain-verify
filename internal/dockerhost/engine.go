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

// Published is one host port a container publishes.
type Published struct {
	Container string
	HostIP    string
	HostPort  string
	Proto     string
}

// PublishedPorts lists host port bindings via GET on a local engine socket.
// explicit "off" queries nothing. A remote DOCKER_HOST is returned in remote
// and never contacted. err is set only when a local socket was found but
// the GET failed.
func PublishedPorts(explicit string, getenv func(string) string) (ports []Published, remote string, err error) {
	if explicit == "off" || getenv == nil {
		return nil, "", nil
	}
	socks, remote := socketCandidates(explicit, getenv)
	var sock string
	for _, s := range socks {
		if isSocket(s) {
			sock = s
			break
		}
	}
	if sock == "" {
		return nil, remote, nil
	}
	eng := newEngine(sock, 3*time.Second)
	var sums []apiContainerSummary
	if err = eng.get("/containers/json?all=1", &sums); err != nil {
		return nil, remote, err
	}
	for _, sum := range sums {
		if len(sum.ID) < 12 || strings.IndexFunc(sum.ID, func(r rune) bool {
			return (r < '0' || r > '9') && (r < 'a' || r > 'f')
		}) >= 0 {
			continue
		}
		var c apiContainer
		if err = eng.get("/containers/"+sum.ID+"/json", &c); err != nil {
			return nil, remote, err
		}
		name := containerName(c, sum)
		add := func(key string, binds []apiPortBinding) {
			proto := "tcp"
			if i := strings.LastIndex(key, "/"); i >= 0 {
				proto = key[i+1:]
			}
			for _, b := range binds {
				if b.HostPort == "" {
					continue
				}
				ports = append(ports, Published{Container: name, HostIP: b.HostIP, HostPort: b.HostPort, Proto: proto})
			}
		}
		for k, binds := range c.NetworkSettings.Ports {
			add(k, binds)
		}
		for k, binds := range c.HostConfig.PortBindings {
			add(k, binds)
		}
	}
	return ports, remote, nil
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
