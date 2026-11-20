package reposcan

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	shaRefRe = regexp.MustCompile(`^[0-9a-f]{40}$`)
	// Attacker-controlled contexts (GitHub "untrusted input" list).
	taintedExprRe   = regexp.MustCompile(`\$\{\{[^}]*\b(github\.event\.(issue\.(title|body)|pull_request\.(title|body|head\.ref|head\.label|head\.repo\.default_branch)|comment\.body|review\.body|review_comment\.body|discussion\.(title|body)|pages\.[^}]*page_name|commits\.[^}]*\.(message|author\.(email|name))|head_commit\.(message|author\.(email|name))|workflow_run\.(head_branch|head_commit\.message|display_title)|issue_comment\.body)|github\.head_ref)\b[^}]*\}\}`)
	sameRepoGuardRe = regexp.MustCompile(`head_repository\.full_name\s*==\s*github\.repository|pull_request\.head\.repo\.full_name\s*==\s*github\.repository|github\.repository\s*==\s*github\.event\.(pull_request\.head\.repo|workflow_run\.head_repository)\.full_name`)
	prHeadRefRe     = regexp.MustCompile(`github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref|refs/pull/|github\.event\.workflow_run\.head_(sha|branch)|steps\.[a-z0-9_-]+\.outputs\.(head_)?(sha|ref)`)
)

type wfDoc struct {
	on         map[string]bool
	privileged bool
}

// scanWorkflow parses a GitHub Actions workflow or action.yml structurally.
func (s *scanner) scanWorkflow(rel string, b []byte) {
	var root yaml.Node
	if err := yaml.Unmarshal(b, &root); err != nil {
		s.unparsed(rel, "cannot parse YAML: "+err.Error(), Finding{Rule: "config.parse-error", Severity: SevWarn, Path: rel, Message: "workflow YAML could not be parsed: " + err.Error()})
		return
	}
	if len(root.Content) == 0 {
		return
	}
	doc := root.Content[0]
	s.yamlDupKeys(rel, doc, 0)
	wf := wfDoc{on: map[string]bool{}}
	if on := ymap(doc, "on"); on != nil {
		switch on.Kind {
		case yaml.ScalarNode:
			wf.on[on.Value] = true
		case yaml.SequenceNode:
			for _, e := range on.Content {
				wf.on[e.Value] = true
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(on.Content); i += 2 {
				wf.on[on.Content[i].Value] = true
			}
		}
	}
	s.checkAgentPublishJobs(rel, doc, wf.on)
	s.checkWorkflowThreatIntel(rel, doc, wf.on)
	wf.privileged = wf.on["pull_request_target"] || wf.on["workflow_run"] || wf.on["issue_comment"] || wf.on["issues"] || wf.on["discussion"] || wf.on["discussion_comment"] || wf.on["pull_request_review_comment"]
	if p := ymap(doc, "permissions"); p != nil && p.Kind == yaml.ScalarNode && p.Value == "write-all" {
		s.add(Finding{Rule: "gha.write-all", Severity: SevWarn, Path: rel, Line: p.Line, Message: "workflow grants permissions: write-all to GITHUB_TOKEN"})
	}
	type jobSteps struct {
		cond       string
		steps      []*yaml.Node
		privileged bool
	}
	var all []jobSteps
	var unpinned []*unpinnedUse
	untrusted, _ := agentTriggers(wf.on)
	wfPerms := ymap(doc, "permissions")
	if jobs := ymap(doc, "jobs"); jobs != nil && jobs.Kind == yaml.MappingNode {
		for i := 1; i < len(jobs.Content); i += 2 {
			job := jobs.Content[i]
			js := jobSteps{privileged: len(untrusted) > 0 && jobHoldsCredentials(job, wfPerms)}
			if u := ymap(job, "uses"); u != nil { // reusable workflow
				if up := s.checkUses(rel, u); up != nil {
					up.privileged = js.privileged
					unpinned = append(unpinned, up)
				}
			}
			if c := ymap(job, "if"); c != nil {
				js.cond = c.Value
			}
			if st := ymap(job, "steps"); st != nil && st.Kind == yaml.SequenceNode {
				js.steps = st.Content
			}
			all = append(all, js)
		}
	}
	if runs := ymap(doc, "runs"); runs != nil { // composite action.yml
		if st := ymap(runs, "steps"); st != nil && st.Kind == yaml.SequenceNode {
			all = append(all, jobSteps{steps: st.Content})
		}
	}
	checkedOutPR := false
	var submoduleLines []int
	for _, js := range all {
		// A job gated to same-repository heads (not forks) does not run
		// attacker code even under a privileged trigger.
		sameRepo := sameRepoGuardRe.MatchString(js.cond)
		for _, st := range js.steps {
			if c := ymap(st, "if"); c != nil && sameRepoGuardRe.MatchString(c.Value) {
				sameRepo = true
			}
			if l := checkoutSubmodules(st); l > 0 {
				submoduleLines = append(submoduleLines, l)
			}
			if u := ymap(st, "uses"); u != nil {
				if up := s.checkUses(rel, u); up != nil {
					up.privileged = js.privileged
					unpinned = append(unpinned, up)
				}
				if strings.HasPrefix(strings.ToLower(u.Value), "actions/checkout@") {
					if with := ymap(st, "with"); with != nil {
						if ref := ymap(with, "ref"); ref != nil && prHeadRefRe.MatchString(ref.Value) {
							checkedOutPR = true
							if wf.privileged {
								sev, msg := SevFail, "privileged trigger ("+strings.Join(keys(wf.on), ", ")+") checks out untrusted PR code; later build/test steps run it with secrets and a write token"
								if p := ymap(with, "path"); p != nil && p.Value != "" && p.Value != "." {
									sev, msg = SevWarn, "privileged trigger checks out untrusted PR code into "+p.Value+"/; safe only if it is read strictly as data (no build, install, scripts or config from it)"
								}
								if sameRepo {
									sev, msg = SevInfo, "privileged trigger checks out a head ref, but the job is gated to same-repository heads"
								}
								s.add(Finding{Rule: "gha.pwn-request", Severity: sev, Path: rel, Line: ref.Line, Evidence: escapeEvidence(ref.Value, 100), Message: msg,
									Fix:  "use pull_request (unprivileged) for building PR code, or split into an unprivileged build + privileged workflow_run that only reads artifacts as data",
									Refs: []string{"https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/"}})
							}
						}
					}
				}
				if strings.HasPrefix(strings.ToLower(u.Value), "actions/github-script@") {
					if with := ymap(st, "with"); with != nil {
						if sc := ymap(with, "script"); sc != nil {
							s.checkRunInjection(rel, sc, "github-script")
						}
					}
				}
			}
			if run := ymap(st, "run"); run != nil {
				s.checkRunInjection(rel, run, "run")
				sig := signals(canonical(run.Value))
				if sig[sigPipeShell] || (sig[sigDecode] && sig[sigExec]) || (sig[sigSecretRead] && sig[sigExfil]) {
					s.add(Finding{Rule: "gha.risky-run", Severity: SevWarn, Path: rel, Line: run.Line, Evidence: escapeEvidence(run.Value, evidenceRunes), Signals: sigList(sig),
						Message: "workflow step pipes a download to a shell, decodes-and-executes, or sends secrets to an exfil endpoint"})
				}
			}
		}
	}
	s.reportUnpinned(rel, unpinned, untrusted)
	s.reportCheckoutSubmodules(rel, submoduleLines)
	if wf.on["pull_request_target"] && !checkedOutPR {
		s.add(Finding{Rule: "gha.pull-request-target", Severity: SevInfo, Path: rel, Message: "pull_request_target runs with secrets for fork PRs; keep it free of PR code checkouts"})
	}
}

// jobHoldsCredentials: the job references a secret or has a write grant
// (its own permissions, else the workflow's).
func jobHoldsCredentials(job, wfPerms *yaml.Node) bool {
	var all []*yaml.Node
	scalars(job, &all)
	for _, n := range all {
		if secretRefRe.MatchString(n.Value) {
			return true
		}
	}
	perms := ymap(job, "permissions")
	if perms == nil {
		perms = wfPerms
	}
	return len(writePerms(perms)) > 0
}

func (s *scanner) checkRunInjection(rel string, run *yaml.Node, where string) {
	for _, m := range taintedExprRe.FindAllString(run.Value, -1) {
		s.add(Finding{Rule: "gha.script-injection", Severity: SevFail, Path: rel, Line: run.Line, Evidence: escapeEvidence(m, 120),
			Message: "attacker-controlled expression interpolated directly into " + where + ": a crafted title/body/branch name becomes shell or JS code",
			Fix:     "pass it through env: (e.g. env: TITLE: ${{ github.event.issue.title }}) and use \"$TITLE\" quoted",
			Refs:    []string{"https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections"}})
	}
}

// unpinnedUse is one remote action reference that is not pinned to a
// full commit SHA.
type unpinnedUse struct {
	ref        string
	line       int
	firstParty bool
	noRef      bool
	privileged bool // job with secrets/write token under an untrusted trigger
}

// firstPartyAction: actions/* and github/* are published by GitHub.
func firstPartyAction(ref string) bool {
	l := strings.ToLower(ref)
	return strings.HasPrefix(l, "actions/") || strings.HasPrefix(l, "github/")
}

// checkUses inspects one uses: value. Images are reported directly;
// unpinned remote actions are returned for per-file aggregation.
func (s *scanner) checkUses(rel string, u *yaml.Node) *unpinnedUse {
	v := strings.TrimSpace(u.Value)
	if v == "" || strings.HasPrefix(v, "./") {
		return nil // local action: versioned with the repo
	}
	if strings.HasPrefix(v, "docker://") {
		if !strings.Contains(v, "@sha256:") {
			s.add(Finding{Rule: "gha.unpinned-image", Severity: SevWarn, Path: rel, Line: u.Line, Evidence: escapeEvidence(v, 120),
				Message: "container action not pinned by digest"})
		}
		return nil
	}
	at := strings.LastIndex(v, "@")
	if at < 0 {
		return &unpinnedUse{ref: v, line: u.Line, firstParty: firstPartyAction(v), noRef: true}
	}
	if !shaRefRe.MatchString(v[at+1:]) {
		return &unpinnedUse{ref: v, line: u.Line, firstParty: firstPartyAction(v)}
	}
	return nil
}

// reportUnpinned emits gha.unpinned-action: one aggregated finding per
// workflow file (warn when a third-party action is unpinned, info when only
// GitHub's own actions/* and github/* are), plus a separate warn for each
// unpinned third-party action in a privileged job.
func (s *scanner) reportUnpinned(rel string, uses []*unpinnedUse, untrusted []string) {
	var agg []*unpinnedUse
	for _, u := range uses {
		if u.privileged && !u.firstParty {
			msg := "third-party action pinned to a mutable tag/branch in a job that holds secrets or a write token under an untrusted trigger (" + strings.Join(untrusted, ", ") + "); a moved tag runs attacker code with them (tj-actions, March 2025)"
			if u.noRef {
				msg = "third-party action without a ref in a job that holds secrets or a write token under an untrusted trigger (" + strings.Join(untrusted, ", ") + ")"
			}
			s.add(Finding{Rule: "gha.unpinned-action", Severity: SevWarn, Path: rel, Line: u.line, Evidence: escapeEvidence(u.ref, 120), Message: msg,
				Fix:  "pin to the full 40-character commit SHA (keep the tag in a comment)",
				Refs: []string{"https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised"}})
			continue
		}
		agg = append(agg, u)
	}
	if len(agg) == 0 {
		return
	}
	third, first := 0, 0
	seen := map[string]bool{}
	var list []string
	for _, u := range agg {
		if u.firstParty {
			first++
		} else {
			third++
		}
		if !seen[u.ref] {
			seen[u.ref] = true
			list = append(list, u.ref)
		}
	}
	sev := SevInfo
	if third > 0 {
		sev = SevWarn
	}
	s.add(Finding{Rule: "gha.unpinned-action", Severity: sev, Path: rel, Line: agg[0].line, Evidence: escapeEvidence(strings.Join(list, ", "), 400),
		Message: fmt.Sprintf("%d uses: of remote actions not pinned to a commit SHA (%d third-party, %d first-party actions/*, github/*); tags can be moved to a malicious commit (tj-actions, March 2025)", len(agg), third, first),
		Fix:     "pin to the full 40-character commit SHA (keep the tag in a comment); Dependabot/Renovate can keep SHA pins current",
		Refs:    []string{"https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised"}})
}

// yamlDupKeys reports duplicate mapping keys (yaml.v3 accepts them in Node
// mode; GitHub rejects some and silently takes others).
func (s *scanner) yamlDupKeys(rel string, n *yaml.Node, depth int) {
	if n == nil || depth > 64 {
		return
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i].Value
			if seen[k] {
				s.add(Finding{Rule: "config.duplicate-key", Severity: SevWarn, Path: rel, Line: n.Content[i].Line, Evidence: escapeEvidence(k, 80),
					Message: fmt.Sprintf("duplicate YAML key %q; the reviewed value may not be the effective one", k)})
			}
			seen[k] = true
		}
	}
	for _, c := range n.Content {
		s.yamlDupKeys(rel, c, depth+1)
	}
}

func ymap(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	var out *yaml.Node
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			out = n.Content[i+1] // last wins, like most YAML loaders
		}
	}
	return out
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}
