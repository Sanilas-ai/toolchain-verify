package reposcan

import (
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Workflow rules from November 2026 threat intel:
//
//   - wfx-loot (from 2026-11-10): stolen GitHub tokens pushed a CI secret
//     stealer that read every secret through toJSON(secrets), dumped the
//     environment and then deleted the workflow run and its logs.
//   - AI coding agents in GitHub Actions fed untrusted issue/PR/comment
//     text (Codex Action class), and npx/npm -g of unpinned packages
//     (npm hijack).

var (
	secretsJSONRe = regexp.MustCompile(`(?i)\$\{\{[^}]*\btojson\s*\(\s*secrets\s*\)[^}]*\}\}`)
	// echo/printf/cat of a secrets expression on one line.
	secretEchoRe = regexp.MustCompile(`(?im)^[^\n#]*\b(echo|printf|cat|tee)\b[^\n]*\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}`)
	// whole-environment dumps: `env`, `printenv`, `set` piped or redirected
	// (or alone on a line), /proc/*/environ reads.
	envDumpRe = regexp.MustCompile(`(?m)(^|[;&|]\s*|\$\()\s*(env|printenv|export\s+-p)\s*($|[|>;)&])|/proc/(\*|self|[0-9]+|\$[A-Za-z_{}]+)/environ`)
	// deleting workflow runs or their logs from inside a workflow.
	logTamperRe = regexp.MustCompile(`(?i)\bgh\s+run\s+delete\b|actions/runs/[^\s"']*(/logs)?[^\n]*(-X\s*DELETE|--method\s+DELETE)|(-X\s*DELETE|--method\s+DELETE)[^\n]*actions/runs/`)
	// npx / npm -g of a package with no version.
	npxRe         = regexp.MustCompile(`(?m)(?:^|[\s;&|(])npx[ \t]+((?:-[^\s]+[ \t]+)*)(@?[A-Za-z0-9._/-]+(?:@[^\s]+)?)`)
	npmGlobalRe   = regexp.MustCompile(`(?m)(?:^|[\s;&|(])npm[ \t]+(?:i|install|add)[ \t]+(?:-g|--global)[ \t]+((?:[@A-Za-z0-9._/-]+(?:@[^\s]+)?[ \t]*)+)`)
	tiActorGateRe = regexp.MustCompile(`author_association|github\.actor\b|github\.triggering_actor|sender\.login|contains\(\s*fromJSON|github\.event\.comment\.user\.login|github\.event\.issue\.user\.login`)
)

// untrustedTriggers carry text written by anyone who can open an issue,
// comment or fork PR, and run with the base repository's secrets.
var untrustedTriggers = []string{"issues", "issue_comment", "pull_request_target", "pull_request_review_comment", "pull_request_review", "discussion", "discussion_comment"}

// checkWorkflowThreatIntel runs the November 2026 rules over one workflow.
func (s *scanner) checkWorkflowThreatIntel(rel string, doc *yaml.Node, on map[string]bool) {
	var all []*yaml.Node
	scalars(doc, &all)
	for _, n := range all {
		if m := secretsJSONRe.FindString(n.Value); m != "" {
			s.add(Finding{Rule: "gha.secrets-dump", Severity: SevFail, Path: rel, Line: n.Line, Evidence: escapeEvidence(m, 80), CWE: []string{"CWE-200", "CWE-522"},
				Message: "workflow serialises every repository and organisation secret with toJSON(secrets); this is the wfx-loot stealer's collection step and is never needed by a normal job",
				Fix:     "pass only the named secrets a step needs (env: X: ${{ secrets.X }}); if this was not added by you, treat every secret as leaked and rotate",
				Refs:    []string{"https://blog.gitguardian.com/wfx-loot-a-ci-secret-stealer-pushed-with-stolen-github-credentials/"}})
		}
	}
	var runs []*yaml.Node
	collectRuns(doc, &runs)
	for _, r := range runs {
		v := r.Value
		if m := logTamperRe.FindString(v); m != "" {
			s.add(Finding{Rule: "gha.log-tamper", Severity: SevFail, Path: rel, Line: r.Line, Evidence: escapeEvidence(m, 120), CWE: []string{"CWE-117", "CWE-223"},
				Message: "workflow deletes workflow runs or their logs; wfx-loot removed its own run within a minute so a missing run number was the only trace",
				Fix:     "remove the step; log retention belongs in repository settings. Check the Actions history for gaps in run numbers since 2026-11-10",
				Refs:    []string{"https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories"}})
		}
		if m := secretEchoRe.FindString(v); m != "" {
			s.add(Finding{Rule: "gha.secret-echo", Severity: SevWarn, Path: rel, Line: r.Line, Evidence: escapeEvidence(strings.TrimSpace(m), 120), CWE: []string{"CWE-532"},
				Message: "a secrets expression is interpolated into echo/printf/cat; masking is best-effort (encodings, splits, artifacts and files written this way are not masked)",
				Fix:     "pass the secret through env: and never print or write it; upload no file that contains it"})
		} else if m := envDumpRe.FindString(v); m != "" {
			s.add(Finding{Rule: "gha.secret-echo", Severity: SevWarn, Path: rel, Line: r.Line, Evidence: escapeEvidence(strings.TrimSpace(m), 120), CWE: []string{"CWE-532", "CWE-200"},
				Message: "step dumps the whole process environment (env / printenv / /proc/*/environ), which holds every secret mapped into the job",
				Fix:     "print only the variables you need, by name"})
		}
		for _, m := range npxRe.FindAllStringSubmatch(v, -1) {
			flags, pkg := m[1], m[2]
			if strings.Contains(flags, "--no-install") || strings.Contains(flags, "--offline") || pkgPinned(pkg) {
				continue
			}
			s.add(Finding{Rule: "gha.unpinned-npx", Severity: SevWarn, Path: rel, Line: r.Line, Evidence: escapeEvidence(strings.TrimSpace(m[0]), 100), CWE: []string{"CWE-829", "CWE-494"},
				Message: "npx runs " + pkg + " without a pinned version: whatever is published as latest at run time executes with the job's secrets (npm account hijack, typosquat)",
				Fix:     "pin an exact version (npx pkg@1.2.3), or add it to package.json + lockfile and run it from node_modules/.bin"})
		}
		for _, m := range npmGlobalRe.FindAllStringSubmatch(v, -1) {
			for _, pkg := range strings.Fields(m[1]) {
				if strings.HasPrefix(pkg, "-") || pkgPinned(pkg) {
					continue
				}
				s.add(Finding{Rule: "gha.unpinned-npx", Severity: SevWarn, Path: rel, Line: r.Line, Evidence: escapeEvidence(strings.TrimSpace(m[0]), 100), CWE: []string{"CWE-829", "CWE-494"},
					Message: "npm install -g " + pkg + " without a pinned version (npm account hijack, typosquat)",
					Fix:     "pin an exact version (npm i -g pkg@1.2.3)"})
			}
		}
	}
	s.checkAgentUntrustedTrigger(rel, doc, on)
}

// pkgPinned: "pkg@1.2.3" / "@scope/pkg@1.2.3" with a concrete version.
func pkgPinned(pkg string) bool {
	at := strings.LastIndex(pkg, "@")
	if at <= 0 {
		return false
	}
	v := pkg[at+1:]
	return v != "" && v != "latest" && v != "next" && (v[0] >= '0' && v[0] <= '9')
}

func collectRuns(n *yaml.Node, out *[]*yaml.Node) {
	if n == nil {
		return
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i].Value, n.Content[i+1]
			if (k == "run" || k == "script") && v.Kind == yaml.ScalarNode {
				*out = append(*out, v)
				continue
			}
			collectRuns(v, out)
		}
		return
	}
	for _, c := range n.Content {
		collectRuns(c, out)
	}
}

// checkAgentUntrustedTrigger: an AI coding agent step in a workflow that
// anyone can trigger with their own text (issue, comment, fork PR).
func (s *scanner) checkAgentUntrustedTrigger(rel string, doc *yaml.Node, on map[string]bool) {
	var trig []string
	for _, t := range untrustedTriggers {
		if on[t] {
			trig = append(trig, t)
		}
	}
	if len(trig) == 0 {
		return
	}
	jobs := ymap(doc, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		name, job := jobs.Content[i].Value, jobs.Content[i+1]
		gated := false
		if c := ymap(job, "if"); c != nil && tiActorGateRe.MatchString(c.Value) {
			gated = true
		}
		st := ymap(job, "steps")
		if st == nil || st.Kind != yaml.SequenceNode {
			continue
		}
		for _, step := range st.Content {
			agent, line := "", 0
			if u := ymap(step, "uses"); u != nil && agentUsesRe.MatchString(u.Value) {
				agent, line = u.Value, u.Line
			} else if r := ymap(step, "run"); r != nil {
				if m := agentInvocation(r.Value); m != "" {
					agent, line = m, r.Line
				}
			}
			if agent == "" {
				continue
			}
			stepGated := gated
			if c := ymap(step, "if"); c != nil && tiActorGateRe.MatchString(c.Value) {
				stepGated = true
			}
			var vals []*yaml.Node
			scalars(ymap(step, "with"), &vals)
			if r := ymap(step, "run"); r != nil {
				vals = append(vals, r)
			}
			scalars(ymap(step, "env"), &vals)
			tainted := ""
			for _, v := range vals {
				if m := taintedExprRe.FindString(v.Value); m != "" {
					tainted = m
					break
				}
			}
			refs := []string{"https://depi.security/blog/20261111-backdooring-codex/"}
			switch {
			case tainted != "":
				s.add(Finding{Rule: "ci.agent-untrusted-prompt", Severity: SevFail, Path: rel, Line: line, Evidence: escapeEvidence(tainted, 100), CWE: []string{"CWE-77", "CWE-94"},
					Message: "job " + name + " feeds attacker-controlled text (" + strings.Join(trig, ", ") + ") straight into an AI coding agent (" + agent + "): a crafted issue, comment or PR body is a prompt injection with the job's token and secrets",
					Fix:     "gate the job to trusted authors (author_association OWNER/MEMBER/COLLABORATOR), give the agent permissions: contents: read and no secrets, and let it read untrusted text as a file it is told is data",
					Refs:    refs})
			case !stepGated:
				s.add(Finding{Rule: "ci.agent-untrusted-prompt", Severity: SevWarn, Path: rel, Line: line, Evidence: escapeEvidence(agent, 80), CWE: []string{"CWE-77"},
					Message: "job " + name + " runs an AI coding agent (" + agent + ") on " + strings.Join(trig, ", ") + " without an author/actor gate; anyone who can open an issue or comment can steer it",
					Fix:     "add if: contains(fromJSON('[\"OWNER\",\"MEMBER\",\"COLLABORATOR\"]'), github.event.comment.author_association) (or the issue/PR equivalent)",
					Refs:    refs})
			}
		}
	}
}
