package main

import (
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/Sanilas-ai/toolchain-verify/internal/manifest"
	"github.com/Sanilas-ai/toolchain-verify/internal/models"
)

func cmdModels(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("models", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("m", manifest.DefaultFile, "manifest with a [models] section (optional)")
	fs.StringVar(path, "manifest", manifest.DefaultFile, "manifest with a [models] section (optional)")
	noOllama := fs.Bool("no-ollama", false, "skip the Ollama API and model stores")
	noAPI := fs.Bool("no-api", false, "do not query the Ollama API")
	ollamaURL := fs.String("ollama-url", "", "Ollama API base URL (default http://127.0.0.1:11434 or $OLLAMA_HOST)")
	var stores multiFlag
	fs.Var(&stores, "ollama-dir", "Ollama models directory holding blobs/ and manifests/ (repeatable)")
	verify := fs.Bool("verify-blobs", false, "re-hash every referenced Ollama blob (reads every byte)")
	noHash := fs.Bool("no-hash", false, "do not compute SHA-256 of artifacts under the scan roots")
	external := fs.String("external", "", "picklescan/modelscan: auto, require or off (default from manifest, else auto)")
	strict := fs.Bool("strict", false, "warnings fail the run")
	asJSON := fs.Bool("json", false, "print a JSON report")
	verbose := fs.Bool("v", false, "verbose: also print info findings, fixes and the artifact list")
	listArts := fs.Bool("list", false, "print the artifact list (format, size, SHA-256, path)")
	quiet := fs.Bool("q", false, "print nothing when the run passes")
	fs.BoolVar(quiet, "quiet", false, "print nothing when the run passes")
	// flags may follow paths: toolchain-verify models ./model.pt -v
	var paths []string
	for {
		if err := fs.Parse(args); err != nil {
			return 2
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		if args[0] == "--" {
			paths = append(paths, args[1:]...)
			break
		}
		paths = append(paths, args[0])
		args = args[1:]
	}
	switch *external {
	case "", "auto", "require", "off":
	default:
		fmt.Fprintf(stderr, "error: --external wants auto, require or off\n")
		return 2
	}
	cwd, home := cwdHome()
	m, err := policyManifest(fs, *path, cwd, home, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	var pol *models.Policy
	if m != nil && m.Models != nil {
		pol = m.Models
	} else {
		pol = &models.Policy{}
	}
	if *ollamaURL != "" || len(stores) > 0 {
		if pol.Ollama == nil {
			pol.Ollama = &models.Ollama{}
		}
		if *ollamaURL != "" {
			pol.Ollama.URL = *ollamaURL
		}
		if len(stores) > 0 {
			pol.Ollama.ModelsDirs = stores
		}
	}
	rep, err := models.Run(pol, models.Options{Paths: paths, Strict: *strict, NoOllama: *noOllama, NoAPI: *noAPI,
		VerifyBlobs: *verify, NoHash: *noHash, External: *external})
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if *asJSON {
		writeJSON(stdout, rep)
	} else if !(*quiet && rep.OK) {
		printModelsHeader(stdout, rep)
		printFindings(stdout, rep.Findings, *verbose)
		if *verbose || *listArts {
			printArtifacts(stdout, rep)
		}
		verdict(stdout, rep.Findings, rep.OK, rep.Strict, rep.Ignored)
	}
	if !rep.OK {
		return 1
	}
	return 0
}

func printModelsHeader(w io.Writer, rep *models.Report) {
	var size int64
	pickles := 0
	for _, a := range rep.Artifacts {
		size += a.Size
		if a.Pickle {
			pickles++
		}
	}
	parts := []string{fmt.Sprintf("%d artifact(s), %s, %d pickle-based", len(rep.Artifacts), models.Human(size), pickles)}
	if o := rep.Ollama; o != nil {
		api := "API off"
		switch {
		case o.APIError != "":
			api = "API " + o.URL + " unreachable"
		case o.URL != "":
			api = fmt.Sprintf("Ollama %s at %s: %d models", o.Version, o.URL, len(o.APIModels))
		}
		parts = append(parts, api)
		for _, s := range o.Stores {
			parts = append(parts, fmt.Sprintf("store %s: %d manifests, %d blobs (%s), %d orphaned", s.Dir, len(s.Models), s.Blobs, models.Human(s.BlobBytes), len(s.Orphans)))
		}
	}
	if len(rep.Scanners) == 0 {
		parts = append(parts, "external scanners: none")
	} else {
		var n []string
		for k := range rep.Scanners {
			n = append(n, k)
		}
		parts = append(parts, "external scanners: "+strings.Join(n, ", "))
	}
	fmt.Fprintf(w, "toolchain-verify models: %s\n", strings.Join(parts, "; "))
}

func printArtifacts(w io.Writer, rep *models.Report) {
	if len(rep.Artifacts) == 0 {
		return
	}
	fmt.Fprintln(w, "  artifacts:")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, a := range rep.Artifacts {
		sum := a.SHA256
		if len(sum) > 16 {
			sum = sum[:16]
		}
		where := a.Path
		if len(a.Models) > 0 {
			where = strings.Join(a.Models, ",") + " (" + a.Layer + ")"
		}
		fmt.Fprintf(tw, "    %s\t%s\t%s\t%s\t%s\n", a.Format, models.Human(a.Size), orDash(sum), where, a.Details)
	}
	tw.Flush()
}
