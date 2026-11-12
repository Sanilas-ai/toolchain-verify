package reposcan

import (
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Rules from November 2026 incidents:
//   - agent.recursive-clone: agent instructions, scripts and CI that clone
//     with submodules recursively (git CVE-2026-111760 runs code from a
//     malicious repository during such clones).
//   - ci.agent-publish-token: a GitHub Actions job runs an AI coding agent
//     while publish credentials or write/OIDC tokens are in reach (the
//     Codex npm pipeline compromise chain, Depi, 2026-11-11).

var (
	recursiveCloneRe = regexp.MustCompile(`(?i)\bgit\s+(?:-c\s+\S+\s+)*clone\b[^\n;&|]*\s--(?:recurse-submodules|recursive)\b|\bgit\s+submodule\s+update\b[^\n;&|]*\s--recursive\b`)

	agentUsesRe = regexp.MustCompile(`(?i)^(openai/codex-action|anthropics/claude-code-action|anthropics/claude-code-base-action|google-github-actions/run-gemini-cli|cursor/[^@]*agent[^@]*|all-hands-ai/openhands[^@]*|openhands[^@]*|block/goose[^@]*|sst/opencode[^@]*|paul-gauthier/aider[^@]*|aider-ai/[^@]*|github/copilot-[^@]*agent[^@]*)@`)
	agentRunRe  = regexp.MustCompile(`(?i)(^|[\s;&|(/])(codex(\s+exec|\s+-|\s+--|\s*$)|@openai/codex|claude(\s+-p|\s+--print|\s+code)|@anthropic-ai/claude-code|claude-code|cursor-agent|aider(\s|$)|aider-chat|openhands|gemini\s+-p|@google/gemini-cli|goose\s+run|opencode\s+run)`)
	secretRefRe = regexp.MustCompile(`\bsecrets\.([A-Za-z0-9_]+)`)
	publishRe   = regexp.MustCompile(`(?i)^(npm_token|node_auth_token|npm_auth_token|.*pypi.*|twine_.*|cargo_registry_token|gem_host_api_key|rubygems_.*|nuget_.*|ossrh_.*|sonatype_.*|maven_.*|docker(hub)?_(token|password)|gh_pat|.*publish.*|.*release_token.*|.*deploy_key.*|gpg_private_key|signing_key|vsce_pat|ovsx_token|jsr_token)$`)
)

// scanRecursiveClone reports recursive submodule clones in files an agent
// reads as instructions or runs.
func (s *scanner) scanRecursiveClone(rel string, b []byte) {
	text := string(b)
	for _, loc := range recursiveCloneRe.FindAllStringIndex(text, 8) {
		line := 1 + strings.Count(text[:loc[0]], "\n")
		s.add(Finding{Rule: "agent.recursive-clone", Severity: SevWarn, Path: rel, Line: line, Evidence: escapeEvidence(text[loc[0]:loc[1]], 120), CWE: []string{"CWE-829", "CWE-59"},
			Message: "recursive submodule clone: with git < 2.56.1 (CVE-2026-111760) a malicious repository runs code during the clone; agents follow such instructions on untrusted repos",
			Fix:     "clone without submodules (git clone --no-recurse-submodules, -c protocol.file.allow=never), review .gitmodules, then init only the submodules you trust; upgrade git to 2.56.1",
			Refs:    []string{"https://github.com/git/git/security/advisories/GHSA-vp2w-7xxj-jvxr"}})
	}
}

// checkoutSubmodules reports actions/checkout with submodules: recursive.
func (s *scanner) checkoutSubmodules(rel string, st *yaml.Node) {
	u := ymap(st, "uses")
	if u == nil || !strings.HasPrefix(strings.ToLower(u.Value), "actions/checkout@") {
		return
	}
	if with := ymap(st, "with"); with != nil {
		if sm := ymap(with, "submodules"); sm != nil && strings.EqualFold(sm.Value, "recursive") {
			s.add(Finding{Rule: "agent.recursive-clone", Severity: SevWarn, Path: rel, Line: sm.Line, Evidence: "submodules: recursive", CWE: []string{"CWE-829", "CWE-59"},
				Message: "actions/checkout with submodules: recursive runs a recursive submodule clone (CVE-2026-111760 on runners with git < 2.56.1)",
				Fix:     "use submodules: false (or true for one level of trusted submodules) and update the runner's git",
				Refs:    []string{"https://github.com/git/git/security/advisories/GHSA-vp2w-7xxj-jvxr"}})
		}
	}
}

// scalars collects every scalar below n.
func scalars(n *yaml.Node, out *[]*yaml.Node) {
	if n == nil {
		return
	}
	if n.Kind == yaml.ScalarNode {
		*out = append(*out, n)
		return
	}
	for _, c := range n.Content {
		scalars(c, out)
	}
}

// writePerms returns the dangerous grants of a permissions node.
func writePerms(p *yaml.Node) []string {
	if p == nil {
		return nil
	}
	if p.Kind == yaml.ScalarNode {
		if p.Value == "write-all" {
			return []string{"write-all"}
		}
		return nil
	}
	var out []string
	for i := 0; i+1 < len(p.Content); i += 2 {
		k, v := p.Content[i].Value, p.Content[i+1].Value
		if v == "write" && (k == "id-token" || k == "contents" || k == "packages" || k == "actions" || k == "attestations") {
			out = append(out, k+": write")
		}
	}
	return out
}

// checkAgentPublishJobs implements ci.agent-publish-token for one workflow.
func (s *scanner) checkAgentPublishJobs(rel string, doc *yaml.Node) {
	jobs := ymap(doc, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return
	}
	var wfEnv []*yaml.Node
	scalars(ymap(doc, "env"), &wfEnv)
	wfPerms := ymap(doc, "permissions")
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		name, job := jobs.Content[i].Value, jobs.Content[i+1]
		agent, agentLine := "", 0
		if st := ymap(job, "steps"); st != nil && st.Kind == yaml.SequenceNode {
			for _, step := range st.Content {
				if u := ymap(step, "uses"); u != nil && agentUsesRe.MatchString(u.Value) {
					agent, agentLine = u.Value, u.Line
					break
				}
				if r := ymap(step, "run"); r != nil {
					if m := agentRunRe.FindString(r.Value); m != "" {
						agent, agentLine = strings.TrimSpace(strings.TrimLeft(m, " ;&|(/")), r.Line
						break
					}
				}
			}
		}
		if agent == "" {
			continue
		}
		var reach []string
		seen := map[string]bool{}
		var all []*yaml.Node
		scalars(job, &all)
		all = append(all, wfEnv...)
		for _, n := range all {
			for _, m := range secretRefRe.FindAllStringSubmatch(n.Value, -1) {
				if publishRe.MatchString(m[1]) && !seen[m[1]] {
					seen[m[1]] = true
					reach = append(reach, "secrets."+m[1])
				}
			}
		}
		perms := ymap(job, "permissions")
		if perms == nil {
			perms = wfPerms
		}
		reach = append(reach, writePerms(perms)...)
		if len(reach) == 0 {
			continue
		}
		s.add(Finding{Rule: "ci.agent-publish-token", Severity: SevFail, Path: rel, Line: agentLine, Evidence: escapeEvidence(agent, 80), CWE: []string{"CWE-269", "CWE-522"},
			Message: "job " + name + " runs an AI coding agent (" + agent + ") with publish credentials or write tokens in reach: " + strings.Join(reach, ", ") + "; a prompt injection in repository or issue content can turn the agent into a release-pipeline backdoor",
			Fix:     "run the agent in its own job with permissions: contents: read and no publish secrets; publish from a separate job (needs:) on trusted triggers with an environment that requires approval, preferably npm/PyPI trusted publishing (OIDC) scoped to that job only",
			Refs:    []string{"https://depi.security/blog/20261111-backdooring-codex/"}})
	}
}
