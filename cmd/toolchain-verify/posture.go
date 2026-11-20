package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Sanilas-ai/toolchain-verify/internal/agent"
	"github.com/Sanilas-ai/toolchain-verify/internal/check"
	"github.com/Sanilas-ai/toolchain-verify/internal/execpolicy"
	"github.com/Sanilas-ai/toolchain-verify/internal/findings"
	"github.com/Sanilas-ai/toolchain-verify/internal/manifest"
	"github.com/Sanilas-ai/toolchain-verify/internal/pipeline"
)

// cmdPosture runs the session gate: pre-session, exec-policy validate,
// mcp-lock verify, and advisory-database age. The exit status is the
// worst of the four. It adds no new detectors.
func cmdPosture(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("posture", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("m", manifest.DefaultFile, "manifest")
	fs.StringVar(path, "manifest", manifest.DefaultFile, "manifest")
	policyPath := fs.String("policy", "", "exec policy file (default: the usual policy lookup)")
	lockPath := fs.String("lock", "mcp.lock.json", "MCP lock to verify")
	agentEnv := fs.String("agent-env", "", "KEY=VALUE file for the environment the agent will inherit")
	agentNet := fs.String("agent-netns", "", "agent network namespace: none, or anything else (unknown fails closed)")
	var trusted multiFlag
	fs.Var(&trusted, "trusted", "trusted project root (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cwd, home := cwdHome()
	codes := []int{
		postureAdmit(fs, *path, *policyPath, *agentEnv, *agentNet, cwd, home, stdout, stderr),
		posturePreSession(fs, *path, cwd, home, trusted, stdout, stderr),
		posturePolicy(fs, *policyPath, *path, cwd, home, stdout, stderr),
		postureLock(*lockPath, cwd, home, trusted, stdout, stderr),
		postureDBAge(fs, *path, cwd, home, stdout, stderr),
	}
	return worstExit(codes...)
}

func worstExit(codes ...int) int {
	rank := map[int]int{0: 0, 1: 1, 3: 2, 4: 3, 2: 4}
	best, out := 0, 0
	for _, c := range codes {
		if rank[c] > best {
			best, out = rank[c], c
		}
	}
	return out
}

func postureAdmit(fs *flag.FlagSet, manifestPath, policyPath, envPath, netns, cwd, home string, stdout, stderr io.Writer) int {
	opt := agent.Options{Home: home, Cwd: cwd}
	loadAgentPolicy(fs, manifestPath, cwd, home, &opt, stderr)
	var env []string
	if envPath != "" {
		lines, err := pipeline.ParseEnvFile(envPath)
		if err != nil {
			fmt.Fprintln(stderr, "posture admit:", err)
			return 2
		}
		env = lines
	}
	var network *bool
	switch netns {
	case "":
	case "none":
		yes := true
		network = &yes
	default:
		no := false
		network = &no
	}
	in := pipeline.AdmitInput{
		InContainer:      check.DetectContainer(),
		RequireContainer: opt.RequireContainer != nil && *opt.RequireContainer,
		CredPaths: []string{
			filepath.Join(home, ".ssh", "id_ed25519"),
			filepath.Join(home, ".ssh", "id_rsa"),
			filepath.Join(home, ".claude", ".credentials.json"),
			filepath.Join(home, ".codex", "auth.json"),
		},
		GuardPaths: []string{
			filepath.Join(home, ".claude", "settings.json"),
			filepath.Join(home, ".cursor", "hooks.json"),
			filepath.Join(home, ".config", "toolchain-verify", "exec-policy.toml"),
			policyPath,
		},
		AgentEnv:    env,
		NetworkNone: network,
	}
	found := pipeline.Admit(in)
	if len(found) == 0 {
		fmt.Fprintln(stdout, "posture admit: OK")
		return 0
	}
	for _, f := range found {
		fmt.Fprintf(stdout, "posture admit: %s %s\n", f.Rule, f.Message)
	}
	return 1
}

func posturePreSession(fs *flag.FlagSet, manifestPath, cwd, home string, trusted multiFlag, stdout, stderr io.Writer) int {
	opt := agent.Options{Home: home, Cwd: cwd, InContainer: check.DetectContainer(), ExtraTrusted: trusted, NoHostInventory: true}
	pol := loadAgentPolicy(fs, manifestPath, cwd, home, &opt, stderr)
	rep, err := agent.RunPreSession(pol, opt)
	if err != nil && rep == nil {
		fmt.Fprintln(stderr, "posture pre-session:", err)
		return 2
	}
	fmt.Fprintf(stdout, "posture pre-session: exit %d\n", preSessionCode(rep, err))
	return preSessionCode(rep, err)
}

func preSessionCode(rep *agent.Report, err error) int {
	if rep == nil {
		return 2
	}
	if err != nil {
		return exitUntrustedCwd
	}
	if !rep.OK {
		return 1
	}
	if rep.Incomplete {
		return exitIncomplete
	}
	return 0
}

func loadAgentPolicy(fs *flag.FlagSet, manifestPath, cwd, home string, opt *agent.Options, stderr io.Writer) *agent.Policy {
	explicit := flagSet(fs, "m", "manifest")
	mpath := manifestPath
	if !explicit {
		mpath = filepath.Join(cwd, manifest.DefaultFile)
	}
	if !explicit {
		if _, err := os.Stat(mpath); err != nil {
			return nil
		}
	}
	m, err := manifest.Load(mpath)
	if err != nil {
		fmt.Fprintln(stderr, "posture manifest:", err)
		return nil
	}
	opt.RequireContainer = m.RequireContainer
	opt.ManifestDir = m.Dir
	return m.Agent
}

func posturePolicy(fs *flag.FlagSet, policyPath, manifestPath, cwd, home string, stdout, stderr io.Writer) int {
	var pol *execpolicy.Policy
	var src string
	var err error
	if policyPath != "" {
		m, e := manifest.Load(policyPath)
		if e != nil {
			fmt.Fprintln(stderr, "posture policy:", e)
			return 2
		}
		if m.ExecPolicy == nil {
			fmt.Fprintf(stderr, "posture policy: %s has no [exec_policy]\n", policyPath)
			return 2
		}
		pol, src = m.ExecPolicy, policyPath
	} else {
		pfs := flag.NewFlagSet("posture-policy", flag.ContinueOnError)
		pfs.String("m", manifestPath, "")
		pol, src, err = loadExecPolicy(pfs, manifestPath, cwd, home, stderr)
		if err != nil {
			fmt.Fprintln(stderr, "posture policy:", err)
			return 2
		}
	}
	if err := pol.Validate(); err != nil {
		fmt.Fprintln(stderr, "posture policy:", err)
		return 2
	}
	fmt.Fprintf(stdout, "posture policy: %s OK (%d rules)\n", src, len(pol.Rules))
	return 0
}

func postureLock(lockPath, cwd, home string, trusted multiFlag, stdout, stderr io.Writer) int {
	if _, err := os.Stat(lockPath); err != nil {
		fmt.Fprintf(stderr, "posture mcp-lock: %s not found\n", lockPath)
		return exitIncomplete
	}
	opt := agent.Options{Home: home, Cwd: cwd, ExtraTrusted: trusted, NoHostInventory: true, NoBuiltinAdvisories: true}
	lock, err := agent.LoadMCPLock(lockPath)
	if err != nil {
		fmt.Fprintln(stderr, "posture mcp-lock:", err)
		return 2
	}
	servers, err := agent.CollectMCPServers(nil, opt)
	if err != nil {
		fmt.Fprintln(stderr, "posture mcp-lock:", err)
		return 2
	}
	findingsOut := agent.CheckMCPLock(lock, servers)
	fail := false
	for _, f := range findingsOut {
		fmt.Fprintf(stdout, "posture mcp-lock: %s %s\n", f.Rule, f.Message)
		if f.Severity == agent.SevFail {
			fail = true
		}
	}
	if fail {
		return 1
	}
	fmt.Fprintf(stdout, "posture mcp-lock: %s OK\n", lockPath)
	return 0
}

func postureDBAge(fs *flag.FlagSet, manifestPath, cwd, home string, stdout, stderr io.Writer) int {
	opt := agent.Options{Home: home, Cwd: cwd, NoHostInventory: true}
	pol := loadAgentPolicy(fs, manifestPath, cwd, home, &opt, stderr)
	builtin := pol == nil || pol.BuiltinAdvisories == nil || *pol.BuiltinAdvisories
	var extra []string
	if pol != nil {
		extra = pol.Advisories
	}
	db, err := agent.LoadDB(builtin, extra)
	if err != nil {
		fmt.Fprintln(stderr, "posture db:", err)
		return 2
	}
	days := 45
	if pol != nil && pol.DBMaxAgeDays != 0 {
		days = pol.DBMaxAgeDays
	}
	f, stale := findings.StaleDatabase("advisories.toml", db.Updated, time.Now(), days)
	if stale {
		fmt.Fprintf(stdout, "posture db: %s\n", f.Message)
		if pol != nil && pol.Strict {
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "posture db: advisories updated %s\n", db.Updated)
	return 0
}
