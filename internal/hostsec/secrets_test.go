package hostsec

import (
	"strings"
	"testing"

	"github.com/Sanilas-ai/toolchain-verify/internal/findings"
)

// Fake tokens are assembled at runtime so no token-shaped literal lives in
// the repository (and secret scanners stay quiet). None of them is real.
func fakeTok(prefix string, n int) string { return prefix + strings.Repeat("Q7x", n/3+1)[:n] }

func TestSecretsFinderRedacts(t *testing.T) {
	hf := fakeTok("hf_", 34)
	gh := fakeTok("ghp_", 36)
	ant := fakeTok("sk-ant-", 40)
	oai := fakeTok("sk-proj-", 40)
	exch := strings.Repeat("Zk9", 22)
	seed := "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima"

	tr := newTree(t)
	tr.write("/home/dev/.cache/huggingface/token", hf+"\n")
	tr.write("/home/dev/.git-credentials", "https://dev:"+gh+"@github.com\nhttps://ci:"+strings.Repeat("p4ss", 5)+"@git.example.org\n")
	tr.write("/home/dev/proj/.env", "# keys\nANTHROPIC_API_KEY="+ant+"\nOPENAI_API_KEY=\""+oai+"\"\nBINANCE_API_SECRET="+exch+"\nBYBIT_API_KEY=your_key_here\n")
	tr.write("/home/dev/proj/.env.example", "OPENAI_API_KEY="+oai+"\n")
	tr.write("/home/dev/.config/trader/config.json", `{"wallet_mnemonic": "`+seed+`"}`)
	tr.write("/home/dev/.config/google-chrome/Default/Preferences", hf)
	tr.write("/home/dev/.config/app/settings.ini", "token = ${HF_TOKEN}\n")

	env := []string{"PATH=/usr/bin", "GH_TOKEN=" + gh, "KRAKEN_API_SECRET=" + exch, "EDITOR=vim", "DEBUG_TOKEN="}
	rep := run(t, tr, nil, Options{Secrets: true, Environ: env})

	one(t, rep, "host.secret-file", findings.SevWarn, "huggingface-token (hf_…[37 chars])")
	one(t, rep, "host.secret-file", findings.SevWarn, "github-token (git credential for github.com)")
	one(t, rep, "host.secret-file", findings.SevWarn, "git credential for git.example.org")
	one(t, rep, "host.secret-file", findings.SevWarn, "anthropic-api-key (sk-ant-…")
	one(t, rep, "host.secret-file", findings.SevWarn, "openai-api-key (sk-…")
	one(t, rep, "host.secret-file", findings.SevWarn, "binance exchange API key (BINANCE_API_SECRET=<redacted, 66 chars>)")
	one(t, rep, "host.secret-file", findings.SevWarn, "wallet key / seed phrase (wallet_mnemonic=<redacted")
	one(t, rep, "host.secret-env", findings.SevWarn, "KRAKEN_API_SECRET")
	one(t, rep, "host.secret-env", findings.SevInfo, "GH_TOKEN")
	none(t, rep, "host.exchange-key-forbidden")

	for _, f := range rep.Findings {
		all := f.Path + " " + f.Message + " " + f.Fix
		for _, secret := range []string{hf[3:9], gh[4:10], ant[7:13], oai[8:14], exch[:6], "bravo", "p4ssp4ss"} {
			if strings.Contains(all, secret) {
				t.Errorf("finding leaks secret material %q: %s", secret, all)
			}
		}
		for _, bad := range []string{"google-chrome", ".env.example", "settings.ini", "BYBIT", "EDITOR", "DEBUG_TOKEN", "PATH"} {
			if strings.Contains(all, bad) {
				t.Errorf("unexpected finding for %s: %s", bad, all)
			}
		}
	}
	if f := one(t, rep, "host.secret-file", findings.SevWarn, "huggingface"); f.Path != "/home/dev/.cache/huggingface/token:1" {
		t.Errorf("path = %q", f.Path)
	}

	// Sandbox / swarm host: exchange and wallet keys fail.
	rep = run(t, tr, &Policy{Secrets: &SecretsPolicy{ForbidExchangeKeys: true}}, Options{Secrets: true, Environ: env})
	one(t, rep, "host.exchange-key-forbidden", findings.SevFail, "binance exchange API key")
	one(t, rep, "host.exchange-key-forbidden", findings.SevFail, "wallet key / seed phrase")
	one(t, rep, "host.exchange-key-forbidden", findings.SevFail, "KRAKEN_API_SECRET")
	if rep.OK {
		t.Error("run should fail")
	}
	for _, f := range find(rep, "host.secret-file") {
		if strings.Contains(f.Message, "exchange") || strings.Contains(f.Message, "wallet") {
			t.Errorf("exchange key reported twice: %s", f.Message)
		}
	}
}

func TestSecretsNotInDefaultOrApps(t *testing.T) {
	tr := newTree(t)
	tr.write("/home/dev/.cache/huggingface/token", fakeTok("hf_", 34))
	for _, opt := range []Options{{}, {Apps: true}, {Apt: true, Net: true, Vps: true, Apps: true}} {
		rep := run(t, tr, nil, opt)
		none(t, rep, "host.secret-file")
	}
}

func TestSecretsExtraPaths(t *testing.T) {
	tr := newTree(t)
	tr.write("/home/dev/work/creds.txt", "key="+fakeTok("gsk_", 48)+"\n")
	tr.write("/srv/bot/conf.yaml", "okx_passphrase: "+strings.Repeat("Mm3", 6)+"\n")
	rep := run(t, tr, &Policy{Secrets: &SecretsPolicy{ExtraPaths: []string{"~/work", "/srv/bot", "relative/ignored"}}}, Options{Secrets: true})
	one(t, rep, "host.secret-file", findings.SevWarn, "groq-api-key (gsk_…[52 chars])")
	one(t, rep, "host.secret-file", findings.SevWarn, "okx exchange API key (okx_passphrase=<redacted, 18 chars>)")
}
