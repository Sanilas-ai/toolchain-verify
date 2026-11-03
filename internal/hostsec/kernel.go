package hostsec

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Sanilas-ai/toolchain-verify/internal/findings"
)

// Kernel describes the running kernel.
type Kernel struct {
	Release string `json:"release"`           // uname -r, e.g. 5.15.0-202-generic
	Package string `json:"package,omitempty"` // e.g. 5.15.0-202.212 (Ubuntu/Debian)
	Series  string `json:"series"`            // e.g. 5.15
	// Installed lists installed kernel image packages ("name version").
	Installed []string `json:"installed,omitempty"`
}

var (
	ubuntuBuildRe = regexp.MustCompile(`#(\d+)(?:~[^\s]*)?-Ubuntu`)
	debianVerRe   = regexp.MustCompile(`\bDebian (\d[^\s)]*)`)
	releaseRe     = regexp.MustCompile(`^(\d+\.\d+(?:\.\d+)?(?:-\d+)?)`)
)

// runningKernel reads /proc/sys/kernel/osrelease and /proc/version.
func runningKernel(e *env) *Kernel {
	rel, err := e.read("/proc/sys/kernel/osrelease")
	if err != nil {
		return nil
	}
	k := &Kernel{Release: strings.TrimSpace(string(rel))}
	abi := k.Release
	if m := releaseRe.FindString(k.Release); m != "" {
		abi = m
	}
	parts := strings.SplitN(abi, ".", 3)
	if len(parts) >= 2 {
		k.Series = parts[0] + "." + parts[1]
	}
	if ver, err := e.read("/proc/version"); err == nil {
		v := string(ver)
		if m := ubuntuBuildRe.FindStringSubmatch(v); m != nil && strings.Contains(abi, "-") {
			k.Package = abi + "." + m[1] // 5.15.0-202 + .212
		} else if m := debianVerRe.FindStringSubmatch(v); m != nil {
			k.Package = m[1]
		}
	}
	return k
}

// kernelVersion is what floors are compared against.
func (k *Kernel) version() string {
	if k.Package != "" {
		return k.Package
	}
	if m := releaseRe.FindString(k.Release); m != "" {
		return m
	}
	return k.Release
}

var kernelPkgRe = regexp.MustCompile(`^linux-image-(?:unsigned-)?(\d+\.\d+[^ ]*)$`)

func checkKernel(e *env, floors []KernelFloor, rep *Report, dpkg map[string]dpkgPkg, c *findings.Collector) {
	k := runningKernel(e)
	if k == nil {
		c.Add(findings.Finding{Rule: "kernel.unknown", Severity: findings.SevInfo, Path: "/proc/sys/kernel/osrelease",
			Message: "cannot read the running kernel release; kernel checks skipped"})
		return
	}
	rep.Kernel = k
	running := k.version()

	// Installed kernel images newer than the running one.
	type img struct{ release, version string }
	var imgs []img
	seen := map[string]bool{}
	for key, p := range dpkg {
		if strings.Contains(key, ":") || seen[p.Name] {
			continue
		}
		if m := kernelPkgRe.FindStringSubmatch(p.Name); m != nil && p.Status == "installed" {
			seen[p.Name] = true
			imgs = append(imgs, img{m[1], p.Version})
			k.Installed = append(k.Installed, p.Name+" "+p.Version)
		}
	}
	sort.Strings(k.Installed)
	var newest *img
	for i := range imgs {
		if newest == nil || CompareDebVersions(imgs[i].version, newest.version) > 0 {
			newest = &imgs[i]
		}
	}
	runningPkg := ""
	for _, im := range imgs {
		if im.release == k.Release {
			runningPkg = im.version
		}
	}
	if newest != nil && newest.release != k.Release && runningPkg != "" && CompareDebVersions(newest.version, runningPkg) > 0 {
		c.Add(findings.Finding{Rule: "kernel.reboot-pending", Severity: findings.SevWarn, Path: "/proc/sys/kernel/osrelease",
			Message: fmt.Sprintf("running kernel %s (%s) but %s (%s) is installed: its fixes are not active until a reboot", k.Release, runningPkg, newest.release, newest.version),
			Fix:     "reboot into the newest kernel"})
	}

	for _, f := range floors {
		series := f.series()
		if !strings.HasPrefix(k.Release, series+".") && !strings.HasPrefix(k.Release, series+"-") && k.Release != series {
			c.Add(findings.Finding{Rule: "kernel.floor", Severity: findings.SevInfo, Path: "kernel:" + k.Release,
				Message: fmt.Sprintf("%s floor %s applies to the %s series; running %s is not covered (check the vendor tracker)", f.label(), f.Min, series, k.Series), Refs: f.Refs})
			continue
		}
		if CompareDebVersions(running, f.Min) >= 0 {
			c.Add(findings.Finding{Rule: "kernel.floor", Severity: findings.SevInfo, Path: "kernel:" + k.Release,
				Message: fmt.Sprintf("running kernel %s ≥ %s floor %s", running, f.label(), f.Min), Refs: f.Refs})
			continue
		}
		sev := findings.SevFail
		if f.Severity == "warn" {
			sev = findings.SevWarn
		}
		fix := "install a kernel ≥ " + f.Min + " (sudo apt update && sudo apt full-upgrade) and reboot"
		if newest != nil && newest.release != k.Release && CompareDebVersions(newest.version, f.Min) >= 0 {
			fix = "a fixed kernel (" + newest.release + " " + newest.version + ") is already installed: reboot into it"
		}
		c.Add(findings.Finding{Rule: "kernel.floor", Severity: sev, Path: "kernel:" + k.Release,
			Message: fmt.Sprintf("running kernel %s is below the %s floor %s", running, f.label(), f.Min),
			Fix:     fix, Refs: f.Refs})
	}
}

// checkSnaps reports risky snaps (LXD by default) and lxd group membership.
func checkSnaps(e *env, ap AptPolicy, groups func() ([]string, error), c *findings.Collector) {
	for _, name := range ap.WarnSnaps {
		if name == "" || strings.ContainsAny(name, "/*?[") {
			continue
		}
		found := ""
		if e.exists("/snap/" + name + "/current") {
			found = "/snap/" + name
		} else if m := e.glob("/var/lib/snapd/snaps/" + name + "_*.snap"); len(m) > 0 {
			found = m[0]
		}
		if found == "" {
			continue
		}
		msg := "snap " + name + " is installed"
		fix := "remove it if unused: sudo snap remove --purge " + name
		if name == "lxd" {
			msg += ": members of the lxd group can start privileged containers and become root, and LXD has had container-escape CVEs"
			fix = "if LXD is not used: sudo snap remove --purge lxd; otherwise keep the lxd group empty and the snap refreshed"
		}
		c.Add(findings.Finding{Rule: "snap.present", Severity: findings.SevWarn, Path: filepath.ToSlash(found), Message: msg, Fix: fix})
	}
	if gs, err := groups(); err == nil {
		for _, g := range gs {
			if g == "lxd" {
				c.Add(findings.Finding{Rule: "group.lxd", Severity: findings.SevWarn, Path: "group:lxd",
					Message: "the current user is in the lxd group, which is root-equivalent (privileged containers, host mounts)",
					Fix:     "sudo gpasswd -d $USER lxd"})
			}
		}
	}
}
