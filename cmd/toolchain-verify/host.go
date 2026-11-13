package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Sanilas-ai/toolchain-verify/internal/hostsec"
	"github.com/Sanilas-ai/toolchain-verify/internal/manifest"
)

// readInput reads a file, or stdin for "-" (at most 4 MiB).
func readInput(p string, stdin io.Reader) ([]byte, error) {
	if p == "" {
		return nil, nil
	}
	var r io.Reader
	if p == "-" {
		r = stdin
	} else {
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	return io.ReadAll(io.LimitReader(r, 4<<20))
}

func cmdHost(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	var groups []string
	isGroup := func(a string) bool { return a == "apt" || a == "net" || a == "vps" || a == "all" }
	for len(args) > 0 && isGroup(args[0]) {
		groups = append(groups, args[0])
		args = args[1:]
	}
	fs := flag.NewFlagSet("host", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("m", manifest.DefaultFile, "manifest with a [host] section (optional)")
	fs.StringVar(path, "manifest", manifest.DefaultFile, "manifest with a [host] section (optional)")
	root := fs.String("root", "/", "read the host filesystem below this directory (for offline analysis)")
	ufwStatus := fs.String("ufw-status", "", "file with `ufw status verbose` output (\"-\" = stdin); needed when user.rules is root-only")
	ss := fs.String("ss", "", "file with `ss -tulnH` output (\"-\" = stdin) instead of /proc/net")
	profile := fs.String("profile", "", "check profile: \"vps\" (same as the vps group: internet-facing server)")
	sshdT := fs.String("sshd-t", "", "vps: file with `sudo sshd -T` output (\"-\" = stdin); default: evaluate sshd_config + Include drop-ins")
	timedatectl := fs.String("timedatectl", "", "vps: file with `timedatectl show` output (\"-\" = stdin)")
	gitVersion := fs.String("git-version", "", "vps: file with `git --version` output (\"-\" = stdin); default: the dpkg git version")
	nft := fs.String("nft", "", "vps: file with `sudo nft list ruleset` output (\"-\" = stdin)")
	strict := fs.Bool("strict", false, "warnings fail the run")
	asJSON := fs.Bool("json", false, "print a JSON report")
	verbose := fs.Bool("v", false, "verbose: also print info findings and fixes")
	quiet := fs.Bool("q", false, "print nothing when the run passes")
	fs.BoolVar(quiet, "quiet", false, "print nothing when the run passes")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	for _, a := range fs.Args() {
		if !isGroup(a) {
			fmt.Fprintf(stderr, "error: unknown check group %q (want apt, net, vps or all)\n", a)
			return 2
		}
		groups = append(groups, a)
	}
	switch *profile {
	case "":
	case "vps":
		groups = append(groups, "vps")
	default:
		fmt.Fprintf(stderr, "error: unknown profile %q (want vps)\n", *profile)
		return 2
	}
	stdinUsers := 0
	for _, v := range []string{*ufwStatus, *ss, *sshdT, *timedatectl, *gitVersion, *nft} {
		if v == "-" {
			stdinUsers++
		}
	}
	if stdinUsers > 1 {
		fmt.Fprintln(stderr, "error: only one of --ufw-status, --ss, --sshd-t, --timedatectl, --git-version and --nft can read stdin")
		return 2
	}
	cwd, home := cwdHome()
	m, err := policyManifest(fs, *path, cwd, home, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	opt := hostsec.Options{Root: *root, Strict: *strict}
	for _, g := range groups {
		switch g {
		case "apt":
			opt.Apt = true
		case "net":
			opt.Net = true
		case "vps":
			opt.Vps = true
		case "all":
			opt.Apt, opt.Net, opt.Vps = true, true, true
		}
	}
	if opt.UfwStatus, err = readInput(*ufwStatus, stdin); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if opt.SS, err = readInput(*ss, stdin); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	for _, in := range []struct {
		name string
		dst  *[]byte
	}{{*sshdT, &opt.SshdT}, {*timedatectl, &opt.Timedatectl}, {*gitVersion, &opt.GitVersion}, {*nft, &opt.Nft}} {
		if *in.dst, err = readInput(in.name, stdin); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
	}
	var pol *hostsec.Policy
	if m != nil {
		pol = m.Host
	}
	rep, err := hostsec.Run(pol, opt)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if *asJSON {
		writeJSON(stdout, rep)
	} else if !(*quiet && rep.OK) {
		printHostHeader(stdout, rep)
		printFindings(stdout, rep.Findings, *verbose)
		verdict(stdout, rep.Findings, rep.OK, rep.Strict, rep.Ignored)
	}
	if !rep.OK {
		return 1
	}
	return 0
}

func printHostHeader(w io.Writer, rep *hostsec.Report) {
	var parts []string
	if rep.OS != "" {
		parts = append(parts, rep.OS)
	}
	if rep.Kernel != nil {
		k := "kernel " + rep.Kernel.Release
		if rep.Kernel.Package != "" {
			k += " (" + rep.Kernel.Package + ")"
		}
		parts = append(parts, k)
	}
	if rep.Apt != nil && rep.Apt.Installed > 0 {
		parts = append(parts, fmt.Sprintf("%d packages, %d security update(s) pending", rep.Apt.Installed, len(rep.Apt.SecurityPending)))
	}
	if rep.Net != nil {
		n := fmt.Sprintf("%d listeners via %s", len(rep.Net.Listeners), rep.Net.Source)
		if u := rep.Net.Ufw; u != nil {
			state := "inactive"
			if u.Enabled {
				state = "active"
			}
			if u.DefaultIncoming != "" {
				state += ", default " + u.DefaultIncoming
			}
			if u.Source != "" {
				state += fmt.Sprintf(", %d rules from %s", len(u.Rules), u.Source)
			} else {
				state += ", rules unreadable"
			}
			n += "; ufw " + state
		}
		parts = append(parts, n)
	}
	if v := rep.Vps; v != nil {
		s := "vps"
		if v.Hostname != "" {
			s += " " + v.Hostname
		}
		if v.SshdSource != "" {
			s += fmt.Sprintf(", sshd from %s (password %s, root %s)", v.SshdSource, dashIfEmpty(v.Sshd["passwordauthentication"]), dashIfEmpty(v.Sshd["permitrootlogin"]))
		}
		if v.Firewall != "" {
			s += ", firewall " + v.Firewall
		}
		parts = append(parts, s)
	}
	fmt.Fprintf(w, "toolchain-verify host: %s\n", strings.Join(parts, "; "))
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "default"
	}
	return s
}
