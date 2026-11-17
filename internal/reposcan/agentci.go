package reposcan

import (
	"fmt"
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
	secretRefRe = regexp.MustCompile(`\bsecrets\.([A-Za-z0-9_]+)`)
	publishRe   = regexp.MustCompile(`(?i)^(npm_token|node_auth_token|npm_auth_token|.*pypi.*|twine_.*|cargo_registry_token|gem_host_api_key|rubygems_.*|nuget_.*|ossrh_.*|sonatype_.*|maven_.*|docker(hub)?_(token|password)|gh_pat|.*publish.*|.*release_token.*|.*deploy_key.*|gpg_private_key|signing_key|vsce_pat|ovsx_token|jsr_token)$`)
)

const recursiveCloneRisk = "the risk is real only where the cloning git is older than 2.56.1 (CVE-2026-111760: a malicious repository runs code during a recursive clone); agents follow such instructions on untrusted repos"

// lineList renders up to five line numbers.
func lineList(lines []int) string {
	var out []string
	for i, l := range lines {
		if i == 5 {
			out = append(out, "…")
			break
		}
		out = append(out, fmt.Sprint(l))
	}
	return strings.Join(out, ", ")
}

// scanRecursiveClone reports recursive submodule clones in files an agent
// reads as instructions or runs: one finding per file.
func (s *scanner) scanRecursiveClone(rel string, b []byte) {
	text := string(b)
	locs := recursiveCloneRe.FindAllStringIndex(text, -1)
	if len(locs) == 0 {
		return
	}
	var lines []int
	for _, loc := range locs {
		lines = append(lines, 1+strings.Count(text[:loc[0]], "\n"))
	}
	msg := "recursive submodule clone"
	if len(locs) > 1 {
		msg = fmt.Sprintf("%d recursive submodule clones (lines %s)", len(locs), lineList(lines))
	}
	s.add(Finding{Rule: "agent.recursive-clone", Severity: SevWarn, Path: rel, Line: lines[0], Evidence: escapeEvidence(text[locs[0][0]:locs[0][1]], 120), CWE: []string{"CWE-829", "CWE-59"},
		Message: msg + ": " + recursiveCloneRisk,
		Fix:     "update git to 2.56.1 or later wherever this runs (CI runners, agent sandboxes, developer machines), or do not clone untrusted repositories recursively: git clone --no-recurse-submodules (-c protocol.file.allow=never), review .gitmodules, then init only the submodules you trust",
		Refs:    []string{"https://github.com/git/git/security/advisories/GHSA-vp2w-7xxj-jvxr"}})
}

// checkoutSubmodules returns the line of actions/checkout with
// submodules: recursive, or 0.
func checkoutSubmodules(st *yaml.Node) int {
	u := ymap(st, "uses")
	if u == nil || !strings.HasPrefix(strings.ToLower(u.Value), "actions/checkout@") {
		return 0
	}
	if with := ymap(st, "with"); with != nil {
		if sm := ymap(with, "submodules"); sm != nil && strings.EqualFold(sm.Value, "recursive") {
			return sm.Line
		}
	}
	return 0
}

// reportCheckoutSubmodules: one finding per workflow file.
func (s *scanner) reportCheckoutSubmodules(rel string, lines []int) {
	if len(lines) == 0 {
		return
	}
	msg := "actions/checkout with submodules: recursive"
	if len(lines) > 1 {
		msg = fmt.Sprintf("%d actions/checkout steps with submodules: recursive (lines %s)", len(lines), lineList(lines))
	}
	s.add(Finding{Rule: "agent.recursive-clone", Severity: SevWarn, Path: rel, Line: lines[0], Evidence: "submodules: recursive", CWE: []string{"CWE-829", "CWE-59"},
		Message: msg + " runs a recursive submodule clone; " + recursiveCloneRisk + " (GitHub-hosted runners get patched git; self-hosted runners and containers may not)",
		Fix:     "make sure the runner's git is 2.56.1 or later, or use submodules: false (or true for one level of trusted submodules)",
		Refs:    []string{"https://github.com/git/git/security/advisories/GHSA-vp2w-7xxj-jvxr"}})
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

// Triggers for ci.agent-publish-token grading.
var (
	// Events any GitHub user can cause with text the agent will read.
	agentUntrustedEvents = []string{"issue_comment", "issues", "pull_request_target", "pull_request_review", "pull_request_review_comment", "discussion", "discussion_comment", "workflow_run"}
	// Events only people with write access (or the scheduler) can start.
	agentTrustedEvents = map[string]bool{"workflow_dispatch": true, "schedule": true, "push": true, "release": true, "merge_group": true, "create": true, "delete": true, "repository_dispatch": true}

	authorAssocRe  = regexp.MustCompile(`(?i)author_association`)
	trustedAssocRe = regexp.MustCompile(`\b(OWNER|MEMBER|COLLABORATOR)\b`)
	openAssocRe    = regexp.MustCompile(`\b(NONE|CONTRIBUTOR|FIRST_TIME_CONTRIBUTOR|FIRST_TIMER|MANNEQUIN)\b|author_association\s*!=`)
	actorGateRe    = regexp.MustCompile(`github\.(actor|triggering_actor)\s*==\s*'[^']+'|contains\(\s*fromJSON\([^)]*\)\s*,\s*github\.(actor|triggering_actor)\s*\)`)
	builtinCheckRe = regexp.MustCompile(`(?i)^anthropics/claude-code-action@`)
)

// authorGate reports an if: expression that admits only owners, members
// and collaborators (or named actors).
func authorGate(cond string) bool {
	if actorGateRe.MatchString(cond) {
		return true
	}
	return authorAssocRe.MatchString(cond) && trustedAssocRe.MatchString(cond) && !openAssocRe.MatchString(cond)
}

// agentTriggers splits workflow events into untrusted (anyone can cause
// them) and whether every event is trusted (write access or scheduler).
func agentTriggers(on map[string]bool) (untrusted []string, trustedOnly bool) {
	for _, e := range agentUntrustedEvents {
		if on[e] {
			untrusted = append(untrusted, e)
		}
	}
	trustedOnly = len(on) > 0
	for e := range on {
		if !agentTrustedEvents[e] {
			trustedOnly = false
		}
	}
	return
}

// checkAgentPublishJobs implements ci.agent-publish-token for one workflow.
//
// Severity:
//   - fail: an untrusted trigger (issue_comment, issues, pull_request_target,
//     pull_request_review*, discussion*, workflow_run) reaches the agent with
//     no author_association/actor filter and no built-in write check, and the
//     job holds a publish secret or a write/OIDC token; or
//     claude-code-action with allowed_non_write_users: "*".
//   - warn: same, but the job or step is gated to OWNER/MEMBER/COLLABORATOR
//     (or named actors), or only the action's built-in write-permission check
//     protects it (claude-code-action without allowed_non_write_users); also
//     any other trigger mix with publish secrets or contents/packages write.
//   - info: only trusted triggers (dispatch, schedule, push, release) and the
//     only grant is id-token: write (OIDC) with read-only contents.
func (s *scanner) checkAgentPublishJobs(rel string, doc *yaml.Node, on map[string]bool) {
	jobs := ymap(doc, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return
	}
	untrusted, trustedOnly := agentTriggers(on)
	var wfEnv []*yaml.Node
	scalars(ymap(doc, "env"), &wfEnv)
	wfPerms := ymap(doc, "permissions")
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		name, job := jobs.Content[i].Value, jobs.Content[i+1]
		agent, agentLine := "", 0
		var agentStep *yaml.Node
		if st := ymap(job, "steps"); st != nil && st.Kind == yaml.SequenceNode {
			for _, step := range st.Content {
				if u := ymap(step, "uses"); u != nil && agentUsesRe.MatchString(u.Value) {
					agent, agentLine, agentStep = u.Value, u.Line, step
					break
				}
				if r := ymap(step, "run"); r != nil {
					if m := agentInvocation(r.Value); m != "" {
						agent, agentLine, agentStep = m, r.Line, step
						break
					}
				}
			}
		}
		if agent == "" {
			continue
		}
		var reach, secretsReach []string
		seen := map[string]bool{}
		var all []*yaml.Node
		scalars(job, &all)
		all = append(all, wfEnv...)
		for _, n := range all {
			for _, m := range secretRefRe.FindAllStringSubmatch(n.Value, -1) {
				if publishRe.MatchString(m[1]) && !seen[m[1]] {
					seen[m[1]] = true
					secretsReach = append(secretsReach, "secrets."+m[1])
				}
			}
		}
		perms := ymap(job, "permissions")
		if perms == nil {
			perms = wfPerms
		}
		grants := writePerms(perms)
		reach = append(append(reach, secretsReach...), grants...)

		// Who can start the agent?
		gated := false
		if c := ymap(job, "if"); c != nil && authorGate(c.Value) {
			gated = true
		}
		if c := ymap(agentStep, "if"); c != nil && authorGate(c.Value) {
			gated = true
		}
		builtin, openToAll, named := false, false, ""
		if u := ymap(agentStep, "uses"); u != nil && builtinCheckRe.MatchString(u.Value) {
			builtin = true
			if with := ymap(agentStep, "with"); with != nil {
				if a := ymap(with, "allowed_non_write_users"); a != nil && strings.TrimSpace(a.Value) != "" {
					if strings.TrimSpace(a.Value) == "*" {
						openToAll, builtin = true, false
					} else {
						named = strings.TrimSpace(a.Value)
					}
				}
			}
		}
		if len(reach) == 0 && !(openToAll && len(untrusted) > 0) {
			continue
		}

		sev, why := SevWarn, ""
		switch {
		case openToAll && len(untrusted) > 0:
			sev, why = SevFail, "allowed_non_write_users: \"*\" lets any GitHub user drive the agent via "+strings.Join(untrusted, ", ")
		case len(untrusted) > 0 && gated:
			why = "untrusted trigger (" + strings.Join(untrusted, ", ") + ") is gated by an author_association/actor filter"
		case len(untrusted) > 0 && builtin && named != "":
			why = "untrusted trigger (" + strings.Join(untrusted, ", ") + "); protection only inside the action (write-permission check), with named non-write users allowed"
		case len(untrusted) > 0 && builtin:
			why = "untrusted trigger (" + strings.Join(untrusted, ", ") + "); protection only inside the action (its write-permission check), no author_association filter in the workflow"
		case len(untrusted) > 0:
			sev, why = SevFail, "untrusted trigger ("+strings.Join(untrusted, ", ")+") reaches the agent with no author_association filter"
		case trustedOnly && len(secretsReach) == 0 && onlyOIDC(grants):
			sev, why = SevInfo, "only trusted triggers ("+strings.Join(keys(on), ", ")+") and read-only contents; OIDC token in reach"
		case trustedOnly:
			why = "only trusted triggers (" + strings.Join(keys(on), ", ") + "), but the agent reads repository content contributors can influence"
		default:
			why = "triggers: " + strings.Join(keys(on), ", ")
		}
		msg := "job " + name + " runs an AI coding agent (" + agent + ")"
		if len(reach) > 0 {
			msg += " with publish credentials or write tokens in reach: " + strings.Join(reach, ", ")
		}
		msg += "; " + why + "; a prompt injection in repository or issue content can turn the agent into a release-pipeline backdoor"
		s.add(Finding{Rule: "ci.agent-publish-token", Severity: sev, Path: rel, Line: agentLine, Evidence: escapeEvidence(agent, 80), CWE: []string{"CWE-269", "CWE-522"},
			Message: msg,
			Fix:     "run the agent in its own job with permissions: contents: read and no publish secrets; publish from a separate job (needs:) on trusted triggers with an environment that requires approval, preferably npm/PyPI trusted publishing (OIDC) scoped to that job only; gate comment/issue triggers with author_association (OWNER/MEMBER/COLLABORATOR) in the workflow itself",
			Refs:    []string{"https://depi.security/blog/20261111-backdooring-codex/"}})
	}
}

// onlyOIDC: the grants are empty or just id-token: write.
func onlyOIDC(grants []string) bool {
	for _, g := range grants {
		if g != "id-token: write" {
			return false
		}
	}
	return true
}
