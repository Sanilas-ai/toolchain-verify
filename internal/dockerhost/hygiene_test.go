package dockerhost

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Sanilas-ai/toolchain-verify/internal/findings"
)

type fakeContainer struct {
	id   string
	body map[string]any
}

func ctr(id, name, image string, running bool, hc map[string]any, extra map[string]any) fakeContainer {
	b := map[string]any{
		"Id": id, "Name": "/" + name,
		"Config":     map[string]any{"Image": image, "User": ""},
		"State":      map[string]any{"Running": running, "Status": map[bool]string{true: "running", false: "exited"}[running]},
		"HostConfig": hc,
	}
	for k, v := range extra {
		b[k] = v
	}
	return fakeContainer{id: id, body: b}
}

func hexID(c byte) string { return strings.Repeat(string(c), 64) }

// fakeEngine serves a minimal Engine API on a unix socket and records any
// non-GET request.
func fakeEngine(t *testing.T, containers []fakeContainer) (string, *atomic.Int32) {
	t.Helper()
	dir, err := os.MkdirTemp("", "dh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "docker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var bad atomic.Int32
	mux := http.NewServeMux()
	js := func(w http.ResponseWriter, v any) { _ = json.NewEncoder(w).Encode(v) }
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			bad.Add(1)
			http.Error(w, "no", 405)
			return
		}
		switch {
		case r.URL.Path == "/info":
			js(w, map[string]any{"ServerVersion": "29.1.3", "SecurityOptions": []string{"name=apparmor", "name=seccomp,profile=builtin"}})
		case r.URL.Path == "/networks":
			js(w, []map[string]any{{"Name": "bridge", "Internal": false}, {"Name": "isolated", "Internal": true}, {"Name": "agents", "Internal": false}})
		case r.URL.Path == "/containers/json":
			var list []map[string]any
			for _, c := range containers {
				list = append(list, map[string]any{"Id": c.id, "Names": []string{c.body["Name"].(string)}})
			}
			list = append(list, map[string]any{"Id": "../../etc", "Names": []string{"/evil"}})
			js(w, list)
		case strings.HasPrefix(r.URL.Path, "/containers/"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/containers/"), "/json")
			for _, c := range containers {
				if c.id == id {
					js(w, c.body)
					return
				}
			}
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return sock, &bad
}

func get(rep *Report, rule, path string) *findings.Finding {
	for i, f := range rep.Findings {
		if f.Rule == rule && (path == "" || f.Path == path) {
			return &rep.Findings[i]
		}
	}
	return nil
}

func noEnv(string) string { return "" }

func TestHygiene(t *testing.T) {
	bridge := map[string]any{"Networks": map[string]any{"bridge": map[string]any{}}}
	sock, bad := fakeEngine(t, []fakeContainer{
		ctr(hexID('a'), "ollama", "ollama/ollama:latest", true, map[string]any{"NetworkMode": "bridge"},
			map[string]any{"NetworkSettings": map[string]any{"Ports": map[string]any{"11434/tcp": []map[string]string{{"HostIp": "0.0.0.0", "HostPort": "11434"}, {"HostIp": "::", "HostPort": "11434"}}}, "Networks": map[string]any{"bridge": map[string]any{}}}}),
		ctr(hexID('b'), "flowise", "flowiseai/flowise:3.1.4", true,
			map[string]any{"Privileged": true, "CapAdd": []string{"SYS_ADMIN", "CHOWN"}, "NetworkMode": "agents", "SecurityOpt": []string{"seccomp:unconfined"}, "PidMode": "host"},
			map[string]any{"Mounts": []map[string]any{{"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock", "RW": true}, {"Type": "bind", "Source": "/home/u", "Destination": "/h", "RW": true}, {"Type": "bind", "Source": "/home/u/.ssh", "Destination": "/s"}},
				"NetworkSettings": map[string]any{"Networks": map[string]any{"agents": map[string]any{}}}}),
		ctr(hexID('c'), "sandbox", "python@sha256:"+hexID('d'), true, map[string]any{"NetworkMode": "none"},
			map[string]any{"NetworkSettings": map[string]any{"Ports": map[string]any{"8080/tcp": []map[string]string{{"HostIp": "127.0.0.1", "HostPort": "8080"}}}}}),
		ctr(hexID('e'), "old-redis", "redis", false, map[string]any{"NetworkMode": "isolated", "PortBindings": map[string]any{"6379/tcp": []map[string]string{{"HostIp": "", "HostPort": "6379"}}}},
			map[string]any{"NetworkSettings": map[string]any{"Networks": map[string]any{"isolated": map[string]any{}}}}),
		ctr(hexID('f'), "worker-1", "ghcr.io/acme/worker:1.2", true, map[string]any{"NetworkMode": "bridge"}, map[string]any{"NetworkSettings": bridge}),
	})
	os.Chmod(sock, 0o666)
	dir := t.TempDir()
	daemon := filepath.Join(dir, "daemon.json")
	os.WriteFile(daemon, []byte(`{"hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2375"]}`), 0o644)
	unit := filepath.Join(dir, "docker.service")
	os.WriteFile(unit, []byte("[Service]\nExecStart=/usr/bin/dockerd -H fd:// -H tcp://127.0.0.1:2375\n"), 0o644)

	rep, err := Run(&Policy{EgressDeny: []string{"worker-*"}}, Options{
		Home: "/home/u", Socket: sock, Getenv: noEnv, DaemonConfigs: []string{daemon}, SystemdUnits: []string{filepath.Join(dir, "*.service")},
		Groups: func() (string, []string, error) { return "admin", []string{"admin", "docker"}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if bad.Load() != 0 {
		t.Fatalf("audit sent %d non-GET requests", bad.Load())
	}
	if rep.Engine == nil || rep.Engine.Version != "29.1.3" || rep.Containers != 5 || rep.Running != 4 {
		t.Fatalf("engine/containers: %+v %+v", rep.Engine, rep)
	}
	type want struct{ rule, path, sev, contains string }
	for _, w := range []want{
		{"docker.public-bind", "container:ollama", "fail", "11434/tcp -> 0.0.0.0:11434"},
		{"docker.latest-tag", "container:ollama", "warn", "ollama/ollama:latest"},
		{"docker.egress", "container:ollama", "info", "bridge"},
		{"docker.root-user", "container:ollama", "info", ""},
		{"docker.privileged", "container:flowise", "fail", ""},
		{"docker.cap-add", "container:flowise", "fail", "SYS_ADMIN"},
		{"docker.unconfined", "container:flowise", "warn", "seccomp"},
		{"docker.host-pid", "container:flowise", "fail", ""},
		{"docker.socket-mount", "container:flowise", "fail", "docker.sock"},
		{"docker.egress", "container:flowise", "warn", "agent stack"},
		{"docker.public-bind", "container:old-redis", "warn", "6379/tcp -> 0.0.0.0:6379"},
		{"docker.latest-tag", "container:old-redis", "info", "exited"},
		{"docker.egress", "container:worker-1", "fail", "requires no egress"},
		{"docker.daemon-tcp", daemon, "fail", "0.0.0.0:2375"},
		{"docker.daemon-tcp", unit, "warn", "127.0.0.1:2375"},
		{"docker.group-member", "user:admin", "warn", ""},
		{"docker.socket-perms", sock, "fail", "world-writable"},
	} {
		f := get(rep, w.rule, w.path)
		if f == nil {
			t.Errorf("missing %s %s", w.rule, w.path)
			continue
		}
		if f.Severity != w.sev || !strings.Contains(f.Message, w.contains) {
			t.Errorf("%s %s: got %s %q", w.rule, w.path, f.Severity, f.Message)
		}
	}
	var homeMount, credMount bool
	for _, f := range rep.Findings {
		if f.Rule == "docker.host-mount" && strings.Contains(f.Message, "whole home") {
			homeMount = true
		}
		if f.Rule == "docker.host-mount" && strings.Contains(f.Message, "credential") && f.Severity == "fail" {
			credMount = true
		}
		if f.Path == "container:sandbox" && f.Severity != "info" {
			t.Errorf("hardened sandbox container flagged: %+v", f)
		}
		if f.Path == "container:evil" {
			t.Errorf("invalid container id must not be requested")
		}
	}
	if !homeMount || !credMount {
		t.Errorf("host mounts: home=%v cred=%v", homeMount, credMount)
	}
	if get(rep, "docker.egress", "container:sandbox") != nil || get(rep, "docker.egress", "container:old-redis") != nil {
		t.Error("no-egress containers flagged for egress")
	}
	if rep.OK {
		t.Error("report must fail")
	}

	// allow lists
	rep, _ = Run(&Policy{AllowPublicBind: []string{"ollama"}, AllowLatest: []string{"ollama/*"}, AllowDockerGroup: true}, Options{
		Socket: sock, Getenv: noEnv, DaemonConfigs: []string{}, SystemdUnits: []string{},
		Groups: func() (string, []string, error) { return "admin", []string{"docker"}, nil },
	})
	if f := get(rep, "docker.public-bind", "container:ollama"); f == nil || f.Severity != "info" {
		t.Errorf("allow_public_bind: %+v", f)
	}
	if get(rep, "docker.latest-tag", "container:ollama") != nil {
		t.Error("allow_latest")
	}
	if f := get(rep, "docker.group-member", ""); f == nil || f.Severity != "info" {
		t.Errorf("allow_docker_group: %+v", f)
	}
}

func TestEngineUnavailableAndRemote(t *testing.T) {
	none := func() (string, []string, error) { return "u", nil, nil }
	env := func(k string) string {
		return map[string]string{"DOCKER_HOST": "tcp://10.0.0.5:2375"}[k]
	}
	rep, err := Run(nil, Options{Socket: "/nonexistent/docker.sock", Getenv: env, Groups: none, DaemonConfigs: []string{}, SystemdUnits: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if f := get(rep, "docker.engine-unavailable", ""); f == nil || f.Severity != "info" || !rep.OK {
		t.Errorf("unavailable: %+v", rep.Findings)
	}
	if get(rep, "docker.client-tcp", "") == nil {
		t.Errorf("client tcp: %+v", rep.Findings)
	}
	rep, _ = Run(&Policy{RequireEngine: true}, Options{Socket: "/nonexistent/docker.sock", Getenv: noEnv, Groups: none, DaemonConfigs: []string{}, SystemdUnits: []string{}})
	if rep.OK {
		t.Error("require_engine must fail without an engine")
	}
	rep, _ = Run(&Policy{Socket: "off"}, Options{Getenv: env, Groups: none, DaemonConfigs: []string{}, SystemdUnits: []string{}})
	if get(rep, "docker.engine-unavailable", "") != nil {
		t.Error("socket off must skip the engine")
	}
	socks, remote := socketCandidates("", env)
	if remote == "" || socks[0] != "/var/run/docker.sock" {
		t.Errorf("candidates: %v %q", socks, remote)
	}
	socks, _ = socketCandidates("", func(k string) string {
		return map[string]string{"DOCKER_HOST": "unix:///run/user/1000/docker.sock", "XDG_RUNTIME_DIR": "/run/user/1000"}[k]
	})
	if socks[0] != "/run/user/1000/docker.sock" || len(socks) != 5 {
		t.Errorf("unix DOCKER_HOST: %v", socks)
	}
	if _, err := Run(nil, Options{Socket: "relative.sock", Getenv: noEnv, Groups: none}); err == nil {
		t.Error("relative socket must be refused")
	}
	for _, p := range []Policy{{Socket: "x"}, {EgressDeny: []string{"*"}}, {AllowPublicBind: []string{""}}} {
		if p.Validate() == nil {
			t.Errorf("policy %+v should be invalid", p)
		}
	}
}

func TestSplitImageAndWildcard(t *testing.T) {
	for _, c := range []struct{ ref, repo, tag, digest string }{
		{"ollama/ollama", "ollama/ollama", "", ""},
		{"ollama/ollama:latest", "ollama/ollama", "latest", ""},
		{"localhost:5000/x/y:1.2", "localhost:5000/x/y", "1.2", ""},
		{"localhost:5000/x/y", "localhost:5000/x/y", "", ""},
		{"python:3.12@sha256:abc", "python", "3.12", "sha256:abc"},
	} {
		r, tg, d := splitImage(c.ref)
		if r != c.repo || tg != c.tag || d != c.digest {
			t.Errorf("%s: %s %s %s", c.ref, r, tg, d)
		}
	}
	if !wildcard("*flowise*", "docker.io/flowiseai/flowise") || wildcard("worker-*", "web") || !wildcard("Ollama", "ollama") {
		t.Error("wildcard")
	}
}
