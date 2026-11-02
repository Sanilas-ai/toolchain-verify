// Package dockerhost is a read-only hygiene audit of the local Docker or
// Podman host: published ports on all interfaces, privileged containers,
// host namespaces and socket mounts, mutable :latest images, docker group
// membership, a daemon listening on TCP and containers with egress they
// should not need. It reads config files and queries the local Engine API
// with GET requests only; it never starts, stops or modifies anything.
package dockerhost

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Sanilas-ai/toolchain-verify/internal/agent"
	"github.com/Sanilas-ai/toolchain-verify/internal/findings"
)

// Policy is the [docker] table of toolchain.toml.
type Policy struct {
	// Socket is the engine socket (absolute path) or "off". Default:
	// DOCKER_HOST if unix://, then /var/run/docker.sock, rootless and
	// Podman sockets.
	Socket string `toml:"socket"`
	// RequireEngine fails when no engine can be queried.
	RequireEngine bool `toml:"require_engine"`
	// AllowPublicBind: container name or image globs allowed to publish
	// ports on 0.0.0.0 / :: (finding becomes info).
	AllowPublicBind []string `toml:"allow_public_bind"`
	// AllowLatest: container or image globs allowed to run a :latest tag.
	AllowLatest []string `toml:"allow_latest"`
	// EgressDeny: container or image globs that must not have any outbound
	// network (only --network none or internal networks).
	EgressDeny []string `toml:"egress_deny"`
	// AgentImages are extra image globs treated as exec-capable agent
	// stacks (egress is a warning for them).
	AgentImages []string `toml:"agent_images"`
	// AllowDockerGroup downgrades docker group membership to info.
	AllowDockerGroup bool `toml:"allow_docker_group"`
	// Ignore suppresses findings: "rule" or "rule:path-glob" (paths look
	// like "container:NAME").
	Ignore []string `toml:"ignore"`
	// Strict makes warnings fail.
	Strict bool `toml:"strict"`
}

// Validate checks the policy.
func (p *Policy) Validate() error {
	if p.Socket != "" && p.Socket != "off" && !filepath.IsAbs(p.Socket) {
		return fmt.Errorf("docker.socket: want an absolute path or \"off\", got %q", p.Socket)
	}
	for _, g := range append(append(append(append([]string(nil), p.AllowPublicBind...), p.AllowLatest...), p.EgressDeny...), p.AgentImages...) {
		if strings.TrimSpace(g) == "" || g == "*" {
			return fmt.Errorf("docker: glob %q is empty or matches everything", g)
		}
	}
	return nil
}

// DefaultAgentImages are image globs of exec-capable agent stacks.
var DefaultAgentImages = []string{
	"*flowise*", "*langflow*", "*praison*", "*n8n*", "*open-webui*", "*openhands*",
	"*dify*", "*anythingllm*", "*autogpt*", "*open-interpreter*", "*code-interpreter*",
	"*vibe-trading*", "*langalpha*",
}

// EgressLabel on a container (value "none") requires it to have no egress.
const EgressLabel = "toolchain-verify.egress"

// Options carry environment facts; zero values are filled from the process.
type Options struct {
	Home string
	// Socket overrides Policy.Socket.
	Socket string
	Strict bool
	Getenv func(string) string
	// Groups returns the current user's name and group names.
	Groups func() (string, []string, error)
	// DaemonConfigs and SystemdUnits default to the standard locations.
	DaemonConfigs []string
	SystemdUnits  []string
	Timeout       time.Duration
	// MaxContainers caps inspected containers (default 500).
	MaxContainers int
}

// EngineInfo describes the queried engine.
type EngineInfo struct {
	Socket          string   `json:"socket"`
	Version         string   `json:"version,omitempty"`
	Rootless        bool     `json:"rootless,omitempty"`
	SecurityOptions []string `json:"security_options,omitempty"`
}

// Report is the result of a docker hygiene run.
type Report struct {
	Engine     *EngineInfo        `json:"engine,omitempty"`
	Containers int                `json:"containers"`
	Running    int                `json:"running"`
	OK         bool               `json:"ok"`
	Strict     bool               `json:"strict"`
	Findings   []findings.Finding `json:"findings"`
	Ignored    int                `json:"ignored,omitempty"`
}

// Counts returns the number of findings per severity.
func (r *Report) Counts() (fail, warn, info int) { return findings.Counts(r.Findings) }

var (
	// DefaultDaemonConfigs are read (never written) for "hosts".
	DefaultDaemonConfigs = []string{"/etc/docker/daemon.json"}
	// DefaultSystemdUnits are docker.service files and drop-in globs.
	DefaultSystemdUnits = []string{
		"/etc/systemd/system/docker.service", "/etc/systemd/system/docker.service.d/*.conf",
		"/lib/systemd/system/docker.service", "/usr/lib/systemd/system/docker.service",
	}
)

func defaultGroups() (string, []string, error) {
	u, err := user.Current()
	if err != nil {
		return "", nil, err
	}
	ids, err := u.GroupIds()
	if err != nil {
		return u.Username, nil, err
	}
	var names []string
	for _, id := range ids {
		if g, err := user.LookupGroupId(id); err == nil {
			names = append(names, g.Name)
		}
	}
	return u.Username, names, nil
}

// Run performs the audit.
func Run(p *Policy, opt Options) (*Report, error) {
	if p == nil {
		p = &Policy{}
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if opt.Getenv == nil {
		opt.Getenv = os.Getenv
	}
	if opt.Groups == nil {
		opt.Groups = defaultGroups
	}
	if opt.DaemonConfigs == nil {
		opt.DaemonConfigs = DefaultDaemonConfigs
	}
	if opt.SystemdUnits == nil {
		opt.SystemdUnits = DefaultSystemdUnits
	}
	if opt.Timeout <= 0 {
		opt.Timeout = 5 * time.Second
	}
	if opt.MaxContainers <= 0 {
		opt.MaxContainers = 500
	}
	socket := p.Socket
	if opt.Socket != "" {
		socket = opt.Socket
	}
	if socket != "" && socket != "off" && !filepath.IsAbs(socket) {
		return nil, fmt.Errorf("%w: docker socket must be an absolute path: %q", agent.ErrRefused, socket)
	}
	h := &hygiene{p: p, opt: opt, c: &findings.Collector{Ignore: p.Ignore}, rep: &Report{Strict: opt.Strict || p.Strict}}
	h.daemonConfig()
	h.group()
	if socket != "off" {
		h.engineChecks(socket)
	}
	h.rep.Findings = h.c.Sorted()
	h.rep.Ignored = h.c.Ignored
	h.rep.OK = findings.OK(h.rep.Findings, h.rep.Strict)
	return h.rep, nil
}

type hygiene struct {
	p   *Policy
	opt Options
	c   *findings.Collector
	rep *Report
}

func (h *hygiene) add(f findings.Finding) { h.c.Add(f) }

const bypassNote = "Docker's iptables rules bypass ufw/firewalld, so the port is reachable from the network"

// --- daemon config ---------------------------------------------------------

var reTCPHost = regexp.MustCompile(`(?:-H|--host)(?:=|\s+)["']?(tcp://[^\s"']*)`)

func (h *hygiene) daemonConfig() {
	for _, path := range h.opt.DaemonConfigs {
		data, err := readSmall(path)
		if err != nil {
			continue
		}
		var cfg struct {
			Hosts       []string `json:"hosts"`
			TLS         bool     `json:"tls"`
			TLSVerify   bool     `json:"tlsverify"`
			UsernsRemap string   `json:"userns-remap"`
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			h.add(findings.Finding{Rule: "docker.config-invalid", Severity: findings.SevWarn, Path: path, Message: "daemon.json is not valid JSON; dockerd may refuse to start"})
			continue
		}
		for _, host := range cfg.Hosts {
			h.tcpHost(path, host, cfg.TLSVerify)
		}
	}
	for _, pat := range h.opt.SystemdUnits {
		files, _ := filepath.Glob(pat)
		for _, path := range files {
			data, err := readSmall(path)
			if err != nil {
				continue
			}
			text := string(data)
			for _, m := range reTCPHost.FindAllStringSubmatch(text, -1) {
				h.tcpHost(path, m[1], strings.Contains(text, "--tlsverify"))
			}
		}
	}
	if dh := h.opt.Getenv("DOCKER_HOST"); strings.HasPrefix(dh, "tcp://") && h.opt.Getenv("DOCKER_TLS_VERIFY") == "" {
		h.add(findings.Finding{Rule: "docker.client-tcp", Severity: findings.SevWarn, Path: "env:DOCKER_HOST",
			Message: "DOCKER_HOST points to a TCP endpoint without DOCKER_TLS_VERIFY; it is not queried by this audit",
			Fix:     "use the local unix socket or ssh://, or enable TLS client verification"})
	}
}

func (h *hygiene) tcpHost(path, host string, tlsVerify bool) {
	if !strings.HasPrefix(host, "tcp://") {
		return
	}
	addr := strings.TrimPrefix(host, "tcp://")
	local := strings.HasPrefix(addr, "127.") || strings.HasPrefix(addr, "localhost") || strings.HasPrefix(addr, "[::1]")
	sev, msg := findings.SevFail, "dockerd listens on "+host+" without TLS client verification: anyone who can reach it is root on this host"
	switch {
	case tlsVerify && local:
		sev, msg = findings.SevInfo, "dockerd listens on "+host+" with TLS verification"
	case tlsVerify:
		sev, msg = findings.SevWarn, "dockerd listens on "+host+" (TLS verified); make sure the port is firewalled"
	case local:
		sev, msg = findings.SevWarn, "dockerd listens on "+host+" without TLS: every local user and every container that can reach the host loopback is root"
	}
	h.add(findings.Finding{Rule: "docker.daemon-tcp", Severity: sev, Path: path, Message: msg,
		Fix: "remove tcp:// from hosts / -H, or use --tlsverify with client certificates; prefer ssh:// for remote access"})
}

func readSmall(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, 256<<10)
	n, _ := f.Read(buf)
	return buf[:n], nil
}

// --- docker group ----------------------------------------------------------

func (h *hygiene) group() {
	name, groups, err := h.opt.Groups()
	if err != nil {
		return
	}
	for _, g := range groups {
		if g != "docker" {
			continue
		}
		sev := findings.SevWarn
		if h.p.AllowDockerGroup {
			sev = findings.SevInfo
		}
		h.add(findings.Finding{Rule: "docker.group-member", Severity: sev, Path: "user:" + name,
			Message: "user is in the docker group: any process running as this user (including a coding agent) can start a privileged container and become root",
			Fix:     "use rootless Docker or Podman, or run agents as a user outside the docker group (sudo gpasswd -d " + name + " docker); set docker.allow_docker_group = true to accept"})
	}
}

// --- engine ----------------------------------------------------------------

func (h *hygiene) engineChecks(explicit string) {
	socks, remote := socketCandidates(explicit, h.opt.Getenv)
	if remote != "" {
		h.add(findings.Finding{Rule: "docker.remote-host", Severity: findings.SevInfo, Path: "env:DOCKER_HOST",
			Message: "DOCKER_HOST is not a unix socket; remote engines are not queried"})
	}
	var e *engine
	var info apiInfo
	var lastErr error
	for _, s := range socks {
		if !isSocket(s) {
			continue
		}
		h.socketPerms(s)
		cand := newEngine(s, h.opt.Timeout)
		if err := cand.get("/info", &info); err != nil {
			lastErr = err
			continue
		}
		e = cand
		break
	}
	if e == nil {
		sev := findings.SevInfo
		if h.p.RequireEngine {
			sev = findings.SevFail
		}
		msg := "no local Docker/Podman engine socket found"
		if lastErr != nil {
			msg = "engine socket not queryable: " + lastErr.Error()
		}
		h.add(findings.Finding{Rule: "docker.engine-unavailable", Severity: sev, Message: msg})
		return
	}
	ei := &EngineInfo{Socket: e.socket, Version: info.ServerVersion, SecurityOptions: info.SecurityOptions}
	for _, so := range info.SecurityOptions {
		if strings.Contains(so, "rootless") {
			ei.Rootless = true
		}
	}
	h.rep.Engine = ei

	var nets []apiNetwork
	internal := map[string]bool{}
	if err := e.get("/networks", &nets); err == nil {
		for _, n := range nets {
			internal[n.Name] = n.Internal
		}
	}
	var list []apiContainerSummary
	if err := e.get("/containers/json?all=1", &list); err != nil {
		h.add(findings.Finding{Rule: "docker.engine-unavailable", Severity: findings.SevWarn, Path: e.socket, Message: "cannot list containers: " + err.Error()})
		return
	}
	if len(list) > h.opt.MaxContainers {
		h.add(findings.Finding{Rule: "docker.truncated", Severity: findings.SevInfo, Message: fmt.Sprintf("only the first %d of %d containers were inspected", h.opt.MaxContainers, len(list))})
		list = list[:h.opt.MaxContainers]
	}
	for _, sum := range list {
		if !validID(sum.ID) {
			continue
		}
		var c apiContainer
		if err := e.get("/containers/"+sum.ID+"/json", &c); err != nil {
			continue
		}
		h.rep.Containers++
		if c.State.Running {
			h.rep.Running++
		}
		h.container(c, containerName(c, sum), internal, ei.Rootless)
	}
}

var reID = regexp.MustCompile(`^[0-9a-f]{12,64}$`)

func validID(id string) bool { return reID.MatchString(id) }

func (h *hygiene) socketPerms(s string) {
	st, err := os.Stat(s)
	if err != nil {
		return
	}
	if st.Mode().Perm()&0o002 != 0 {
		h.add(findings.Finding{Rule: "docker.socket-perms", Severity: findings.SevFail, Path: s,
			Message: fmt.Sprintf("engine socket is world-writable (%04o): every local user is root", st.Mode().Perm()),
			Fix:     "chmod 0660 " + s + " (owned by root:docker), or use rootless mode"})
	}
}

// --- containers ------------------------------------------------------------

var dangerousCaps = map[string]string{
	"ALL": findings.SevFail, "SYS_ADMIN": findings.SevFail, "SYS_MODULE": findings.SevFail,
	"SYS_PTRACE": findings.SevWarn, "SYS_RAWIO": findings.SevWarn, "DAC_READ_SEARCH": findings.SevWarn,
	"NET_ADMIN": findings.SevWarn, "BPF": findings.SevWarn, "PERFMON": findings.SevWarn, "SYS_BOOT": findings.SevWarn,
}

var hostCritical = []string{"/", "/etc", "/root", "/boot", "/usr", "/var/lib/docker", "/proc", "/sys", "/dev"}

func lower(sev string) string {
	switch sev {
	case findings.SevFail:
		return findings.SevWarn
	case findings.SevWarn:
		return findings.SevInfo
	}
	return sev
}

func (h *hygiene) container(c apiContainer, name string, internal map[string]bool, rootless bool) {
	path := "container:" + name
	repo, tag, digest := splitImage(c.Config.Image)
	state := ""
	add := func(rule, sev, msg, fix string) {
		if !c.State.Running {
			sev = lower(sev)
			if state == "" {
				state = " (container is " + orStr(c.State.Status, "stopped") + ")"
			}
			msg += state
		}
		h.add(findings.Finding{Rule: rule, Severity: sev, Path: path, Message: msg, Fix: fix})
	}
	hc := c.HostConfig

	if hc.Privileged {
		add("docker.privileged", findings.SevFail, "runs --privileged: full access to host devices and kernel, trivially escapes to root",
			"recreate without --privileged; add only the specific --cap-add/--device it needs")
	}
	var caps []string
	capSev := ""
	for _, cp := range hc.CapAdd {
		k := strings.TrimPrefix(strings.ToUpper(cp), "CAP_")
		if s, ok := dangerousCaps[k]; ok {
			caps = append(caps, k)
			if capSev == "" || findings.Rank(s) < findings.Rank(capSev) {
				capSev = s
			}
		}
	}
	if len(caps) > 0 {
		add("docker.cap-add", capSev, "adds dangerous capabilities: "+strings.Join(caps, ", "), "drop them (--cap-drop ALL, add back only what is needed)")
	}
	for _, so := range hc.SecurityOpt {
		s := strings.ReplaceAll(strings.ToLower(so), ":", "=")
		if s == "seccomp=unconfined" || s == "apparmor=unconfined" || s == "label=disable" || s == "systempaths=unconfined" {
			add("docker.unconfined", findings.SevWarn, "security profile disabled: --security-opt "+so, "remove the --security-opt override")
		}
	}
	if hc.PidMode == "host" {
		add("docker.host-pid", findings.SevFail, "shares the host PID namespace (--pid host): can inspect and signal host processes", "remove --pid host")
	}
	if hc.IpcMode == "host" {
		add("docker.host-ipc", findings.SevWarn, "shares the host IPC namespace (--ipc host)", "remove --ipc host")
	}
	for _, m := range c.Mounts {
		src := filepath.Clean(m.Source)
		switch {
		case m.Source == "":
		case strings.HasSuffix(src, "docker.sock") || strings.HasSuffix(src, "podman.sock") || strings.HasSuffix(src, "containerd.sock") || src == "/run" || src == "/var/run":
			add("docker.socket-mount", findings.SevFail, "mounts the container engine socket "+src+": the container controls the engine and is root on the host",
				"remove the socket mount; use a narrowly scoped proxy (e.g. a read-only docker-socket-proxy) if really needed")
		case containsStr(hostCritical, src):
			sev := findings.SevFail
			if !m.RW && src != "/" {
				sev = findings.SevWarn
			}
			add("docker.host-mount", sev, fmt.Sprintf("bind-mounts host %s at %s (%s)", src, m.Destination, rw(m.RW)), "mount only the project directory it needs, read-only")
		case h.opt.Home != "" && src == filepath.Clean(h.opt.Home):
			add("docker.host-mount", findings.SevWarn, fmt.Sprintf("bind-mounts the whole home directory at %s (%s): exposes SSH keys and tokens", m.Destination, rw(m.RW)), "mount only the project directory it needs")
		case h.opt.Home != "" && credentialDir(h.opt.Home, src):
			add("docker.host-mount", findings.SevFail, fmt.Sprintf("bind-mounts credential directory %s at %s", src, m.Destination), "do not mount credential stores into containers; pass a scoped token instead")
		}
	}

	ports := c.NetworkSettings.Ports
	if !c.State.Running || len(ports) == 0 {
		ports = hc.PortBindings
	}
	var public []string
	for cport, binds := range ports {
		for _, b := range binds {
			ip := b.HostIP
			if ip == "" || ip == "0.0.0.0" || ip == "::" || ip == "[::]" {
				public = append(public, fmt.Sprintf("%s -> %s:%s", cport, orStr(ip, "0.0.0.0"), b.HostPort))
			}
		}
	}
	if hc.NetworkMode == "host" {
		add("docker.host-network", findings.SevWarn, "uses the host network (--network host): every port it opens listens on the host interfaces and it has unrestricted egress",
			"use a bridge network and publish only needed ports on 127.0.0.1")
	}
	if len(public) > 0 {
		sort.Strings(public)
		public = uniq(public)
		sev := findings.SevFail
		if h.match(h.p.AllowPublicBind, name, repo) {
			sev = findings.SevInfo
		}
		add("docker.public-bind", sev, "publishes ports on all interfaces: "+strings.Join(public, ", ")+"; "+bypassNote,
			"publish on loopback only (-p 127.0.0.1:PORT:PORT), or list the container in docker.allow_public_bind")
	}

	if digest == "" && (tag == "" || tag == "latest") && repo != "" && !h.match(h.p.AllowLatest, name, repo) {
		add("docker.latest-tag", findings.SevWarn, fmt.Sprintf("runs %s (mutable :latest, no digest): a re-pull silently changes the code", c.Config.Image),
			"pin a version tag and digest (image:1.2.3@sha256:...)")
	}
	if u := c.Config.User; (u == "" || u == "root" || u == "0" || strings.HasPrefix(u, "0:")) && !rootless && hc.UsernsMode != "host" && c.State.Running {
		h.add(findings.Finding{Rule: "docker.root-user", Severity: findings.SevInfo, Path: path, Message: "runs as root inside the container (no user namespace)"})
	}

	// Egress.
	egress, nets := false, []string{}
	switch {
	case hc.NetworkMode == "none":
	case strings.HasPrefix(hc.NetworkMode, "container:"):
	case hc.NetworkMode == "host":
		egress, nets = true, []string{"host"}
	default:
		for n := range c.NetworkSettings.Networks {
			nets = append(nets, n)
		}
		if len(nets) == 0 && hc.NetworkMode != "" {
			nets = []string{hc.NetworkMode}
		}
		sort.Strings(nets)
		for _, n := range nets {
			if n == "none" {
				continue
			}
			if n == "default" {
				n = "bridge"
			}
			if !internal[n] {
				egress = true
			}
		}
	}
	if egress {
		desc := "has outbound network access (networks: " + strings.Join(nets, ", ") + ")"
		fix := "use --network none or an internal network (docker network create --internal), with an explicit egress proxy if it must reach an API"
		switch {
		case strings.EqualFold(c.Config.Labels[EgressLabel], "none") || h.match(h.p.EgressDeny, name, repo):
			add("docker.egress", findings.SevFail, desc+" but policy requires no egress", fix)
		case h.match(append(append([]string(nil), DefaultAgentImages...), h.p.AgentImages...), name, repo):
			add("docker.egress", findings.SevWarn, "exec-capable agent stack "+desc+": a prompt injection can exfiltrate data or pull payloads", fix)
		default:
			add("docker.egress", findings.SevInfo, desc, fix)
		}
	}
}

func rw(b bool) string {
	if b {
		return "read-write"
	}
	return "read-only"
}

func credentialDir(home, src string) bool {
	for _, d := range agent.CredentialDirs(home) {
		if src == d || strings.HasPrefix(src, d+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func (h *hygiene) match(globs []string, name, repo string) bool {
	for _, g := range globs {
		if wildcard(g, name) || wildcard(g, repo) {
			return true
		}
	}
	return false
}

// wildcard matches s against a pattern where '*' matches any run of
// characters (including '/') and '?' one character; case-insensitive.
func wildcard(pat, s string) bool {
	pat, s = strings.ToLower(pat), strings.ToLower(s)
	px, sx, star, mark := 0, 0, -1, 0
	for sx < len(s) {
		switch {
		case px < len(pat) && (pat[px] == '?' || pat[px] == s[sx]):
			px++
			sx++
		case px < len(pat) && pat[px] == '*':
			star, mark = px, sx
			px++
		case star >= 0:
			px = star + 1
			mark++
			sx = mark
		default:
			return false
		}
	}
	for px < len(pat) && pat[px] == '*' {
		px++
	}
	return px == len(pat)
}

// splitImage returns repository, tag and digest of an image reference.
func splitImage(ref string) (repo, tag, digest string) {
	if i := strings.Index(ref, "@"); i >= 0 {
		ref, digest = ref[:i], ref[i+1:]
	}
	repo = ref
	if i := strings.LastIndex(ref, ":"); i >= 0 && !strings.Contains(ref[i+1:], "/") {
		repo, tag = ref[:i], ref[i+1:]
	}
	if strings.HasPrefix(repo, "sha256") && tag != "" && len(tag) == 64 {
		// container created from an image ID
		return repo + ":" + tag, "", tag
	}
	return repo, tag, digest
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func uniq(s []string) []string {
	out := s[:0]
	for i, x := range s {
		if i == 0 || x != s[i-1] {
			out = append(out, x)
		}
	}
	return out
}

func orStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
