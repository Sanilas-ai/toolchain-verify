package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sanilas-ai/toolchain-verify/internal/manifest"
)

func TestHostSecretsGroup(t *testing.T) {
	root := t.TempDir()
	secret := strings.Repeat("Zk9", 20) // fake, never a real key
	p := filepath.Join(root, "home", "dev", "bot", ".env")
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.WriteFile(p, []byte("BINANCE_API_KEY="+secret+"\n"), 0o600)

	var out, errb bytes.Buffer
	if code := run([]string{"host", "secrets", "--root", root, "-v"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s%s", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "host.secret-file") || !strings.Contains(out.String(), "binance exchange API key") {
		t.Errorf("missing finding:\n%s", out.String())
	}
	out.Reset()
	if code := run([]string{"host", "secrets", "--sandbox-host", "--root", root, "--json"}, &out, &errb); code != 1 || !strings.Contains(out.String(), "host.exchange-key-forbidden") {
		t.Fatalf("sandbox host: exit %d:\n%s", code, out.String())
	}
	if strings.Contains(out.String(), secret[:9]) {
		t.Fatal("secret value leaked into the report")
	}
	out.Reset()
	run([]string{"host", "all", "--root", root, "--json"}, &out, &errb)
	if strings.Contains(out.String(), "host.secret-file") || strings.Contains(out.String(), "exchange-key") {
		t.Errorf("secrets must not run as part of all:\n%s", out.String())
	}
	m, err := manifest.Parse([]byte("[host.secrets]\nforbid_exchange_keys = true\nextra_paths = [\"~/bots\"]\n"))
	if err != nil || m.Host == nil || m.Host.Secrets == nil || !m.Host.Secrets.ForbidExchangeKeys || len(m.Host.Secrets.ExtraPaths) != 1 {
		t.Fatalf("[host.secrets] parse: %v %+v", err, m)
	}
}
