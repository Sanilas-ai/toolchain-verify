package agent

import (
	"fmt"
	"strings"
)

// checkStacks matches installs against the advisory database. It returns
// the number of distinct exec-capable stacks seen.
func checkStacks(r *resolved, db *DB, c *collector, installs []Install) int {
	execStacks := map[string]bool{}
	for i := range installs {
		in := &installs[i]
		if in.Stack == "" {
			continue
		}
		s := &db.Stacks[db.stackIndex(in.Stack)]
		if s.CanExec {
			execStacks[s.Name] = true
		}
		v, err := parsePkgVersion(in.Version)
		if err != nil {
			c.add(Finding{Rule: "stack.unknown-version", Severity: SevWarn, Path: in.Path,
				Message: fmt.Sprintf("%s %s: cannot parse version %q; cannot check advisories", s.Name, in.Package, in.Version)})
			continue
		}
		advs := db.advisoriesFor(s, in.Package, v)
		installed := in.Source == "dist-info" || in.Source == "node_modules" || in.Source == "pnpm"
		where := map[bool]string{true: "installed", false: "pinned in " + in.Source}[installed]
		for _, a := range advs {
			in.Vulnerable = append(in.Vulnerable, a.ID)
			sev := SevFail
			if a.Action == "warn" {
				sev = SevWarn
				if name, val, ok := strings.Cut(a.EscalateEnv, "="); ok && r.getenv(name) == val {
					sev = SevFail
				}
			}
			ids := a.ID
			if len(a.Aliases) > 0 {
				ids += " / " + strings.Join(a.Aliases, ", ")
			}
			msg := fmt.Sprintf("%s %s %s (%s) is affected by %s [%s]: %s", s.Name, in.Package, in.Version, where, ids, a.Severity, a.Summary)
			if a.Condition != "" {
				msg += " Condition: " + a.Condition
			}
			fix := "upgrade to " + a.Fixed + " or later"
			if a.Fixed == "" {
				fix = "no fixed release published: disable the affected feature or stop the service"
			}
			if s.Notes != "" {
				fix += "; " + s.Notes
			}
			c.add(Finding{Rule: "stack.vulnerable", Severity: sev, Path: in.Path, Message: msg, Fix: fix, Refs: a.Refs})
		}
		if len(advs) == 0 {
			c.add(Finding{Rule: "stack.present", Severity: SevInfo, Path: in.Path,
				Message: fmt.Sprintf("%s %s %s (%s): no known advisory in the database (updated %s)", s.Name, in.Package, in.Version, where, db.Updated)})
		}
		if installed && s.CanExec && r.requireExecCont && !r.inContainer {
			c.add(Finding{Rule: "stack.exec-on-host", Severity: SevFail, Path: in.Path,
				Message: fmt.Sprintf("exec-capable agent stack %s is installed on the host (not in a container); prompt injection in content it reads becomes code execution with your user's files and credentials", s.Name),
				Fix:     "run it only inside a disposable non-root container with an empty env and egress allow-list, or set agent.require_container_for_exec = false to accept the risk"})
		}
	}
	return len(execStacks)
}
