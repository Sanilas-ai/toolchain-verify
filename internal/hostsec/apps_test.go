package hostsec

import (
	"strings"
	"testing"

	"github.com/Sanilas-ai/toolchain-verify/internal/findings"
)

// Synthetic keys and extension directories only.
func TestAppsGroup(t *testing.T) {
	tr := newTree(t)
	tr.write("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\ndev:x:1000:1000::/home/dev:/bin/bash\n")
	tr.write("/usr/share/code/resources/app/package.json", `{"name":"code-oss-dev","version":"1.145.2"}`)
	tr.write("/home/dev/.cursor/extensions/anthropic.claude-code-2.1.313-darwin-arm64/package.json", "{}")
	tr.write("/home/dev/.cursor/extensions/anthropic.claude-code-2.1.314/package.json", "{}")
	tr.write("/home/dev/.vscode/extensions/evil.thing-0.0.1/package.json", "{}")
	good, planted := fakeEd25519(1), fakeEd25519(50)
	tr.write("/home/dev/.ssh/authorized_keys", "ssh-ed25519 "+good+" dev@laptop\nssh-ed25519 "+planted+" svc-telemetry\n")

	pol := &Policy{Apps: &AppsPolicy{ExtensionDenylist: []string{"evil.thing@*"}}}
	rep := run(t, tr, pol, Options{Apps: true, LlamaVersion: []byte("version: 12000 (abcdef0)\nbuilt with cc\n"), KeysBaseline: []byte("ssh-ed25519 " + good + " dev@laptop\n")})
	one(t, rep, "host.vscode-cve-2026-120779", findings.SevFail, "1.145.2")
	one(t, rep, "host.llama-server-stale", findings.SevFail, "b12000")
	one(t, rep, "host.ide-extension-denylist", findings.SevFail, "anthropic.claude-code 2.1.313")
	one(t, rep, "host.ide-extension-denylist", findings.SevFail, "evil.thing 0.0.1")
	for _, f := range find(rep, "host.ide-extension-denylist") {
		if strings.Contains(f.Path, "2.1.314") {
			t.Errorf("clean version flagged: %s", f.Path)
		}
	}
	ioc := one(t, rep, "host.ssh-ioc-key", findings.SevFail, "svc-telemetry")
	base := one(t, rep, "host.authorized-keys-baseline", findings.SevFail, "not in the baseline")
	if len(find(rep, "host.authorized-keys-baseline")) != 1 || !strings.HasSuffix(base.Path, "authorized_keys:2") || !strings.HasSuffix(ioc.Path, "authorized_keys:2") {
		t.Errorf("baseline/ioc location:\n%s", dump(rep))
	}
	for _, f := range rep.Findings {
		if strings.Contains(f.Message+f.Path+f.Fix, planted) || strings.Contains(f.Message, "SHA256:") {
			t.Fatalf("key material in report: %+v", f)
		}
	}
	if find(rep, "host.firewall-off") != nil || rep.Apt != nil {
		t.Error("apps alone must not run other groups")
	}

	// fixed versions pass
	tr.write("/usr/share/code/resources/app/package.json", `{"name":"code-oss-dev","version":"1.145.3"}`)
	rep = run(t, tr, nil, Options{Apps: true, LlamaVersion: []byte("version: 1.0.0 (4cda622)\n")})
	none(t, rep, "host.vscode-cve-2026-120779")
	none(t, rep, "host.llama-server-stale")
	rep = run(t, tr, nil, Options{Apps: true, VSCodeVersion: []byte("1.140.0\nabc\nx64\n"), LlamaVersion: []byte("version: 12340 (8954f19)\n")})
	one(t, rep, "host.vscode-cve-2026-120779", findings.SevFail, "1.140.0")
	one(t, rep, "host.llama-server-stale", findings.SevInfo, "b12340")
}

func TestAppsPolicyValidate(t *testing.T) {
	if err := (&Policy{Apps: &AppsPolicy{ExtensionDenylist: []string{"nodot@1"}}}).Validate(); err == nil {
		t.Error("bad spec accepted")
	}
	if b, s := LlamaBuild("ggml b4523"); b != 4523 || s != "" {
		t.Errorf("tag form: %d %q", b, s)
	}
}
