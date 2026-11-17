package hostsec

import (
	"testing"

	"github.com/Sanilas-ai/toolchain-verify/internal/dockerhost"
)

func TestDockerPublishedBypass(t *testing.T) {
	tr := netTree(t)
	open := []dockerhost.Published{{Container: "web", HostIP: "0.0.0.0", HostPort: "8080", Proto: "tcp"}}
	rep := run(t, tr, nil, Options{Net: true, DockerPorts: &open})
	if len(find(rep, "net.docker-bypass")) != 1 {
		t.Fatalf("published port: %+v", rep.Findings)
	}
	loop := []dockerhost.Published{{Container: "web", HostIP: "127.0.0.1", HostPort: "8080", Proto: "tcp"}}
	rep = run(t, tr, nil, Options{Net: true, DockerPorts: &loop})
	if len(find(rep, "net.docker-bypass")) != 0 {
		t.Fatalf("loopback publish: %+v", find(rep, "net.docker-bypass"))
	}
}
